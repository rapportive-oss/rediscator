require 'thor'

require File.join(File.dirname(__FILE__), 'util')

module Rediscator
  class App < Thor
    namespace :rediscator

    include Thor::Actions
    include Util

    REQUIRED_PACKAGES = %w(
      git-core
      build-essential
      tcl8.5
      pwgen
      s3cmd
      openjdk-6-jre-headless
      unzip
    )

    OPENJDK_JAVA_HOME = '/usr/lib/jvm/java-6-openjdk'

    REDIS_USER = 'redis'
    REDIS_REPO = 'https://github.com/antirez/redis.git'

    CLOUDWATCH_USER = 'cloudwatch'
    CLOUDWATCH_TOOLS_ZIP = 'CloudWatch-2010-08-01.zip'
    CLOUDWATCH_TOOLS_URL = "http://ec2-downloads.s3.amazonaws.com/#{CLOUDWATCH_TOOLS_ZIP}"

    CONFIG_SUBSTITUTIONS = {
      /^daemonize .*$/ => 'daemonize yes',
      /^pidfile .*$/ => 'pidfile [REDIS_PATH]/tmp/redis.pid',
      /^loglevel .*$/ => 'loglevel notice',
      /^logfile .*$/ => 'logfile [REDIS_PATH]/log/redis.log',
      /^dir .*$/ => 'dir [REDIS_PATH]',
      /^# requirepass .*$/ => 'requirepass [REDIS_PASSWORD]',
    }

    desc 'setup', 'Set up Redis'
    method_option :machine_name, :default => `hostname`, :desc => "Name identifying this Redis machine"
    method_option :machine_role, :default => 'redis', :desc => "Description of this machine's role"
    method_option :ec2, :default => false, :type => :boolean, :desc => "Whether this instance is on EC2"
    method_option :cloudwatch_namespace, :default => `hostname`, :desc => "Namespace for CloudWatch metrics"
    method_option :sns_topic, :desc => "Simple Notification Service topic ARN for alarm notifications"
    method_option :redis_version, :required => true, :desc => "Version of Redis to install"
    method_option :run_tests, :default => false, :type => :boolean, :desc => "Whether to run the Redis test suite"
    method_option :backup_tempdir, :default => '/tmp', :desc => "Temporary directory for daily backups"
    method_option :backup_s3_prefix, :required => true, :desc => "S3 bucket and prefix for daily backups, e.g. s3://backups/redis"
    method_option :aws_access_key, :required => true, :desc => "AWS access key ID for backups and monitoring"
    method_option :aws_secret_key, :required => true, :desc => "AWS secret access key for backups and monitoring"
    def setup
      redis_version = options[:redis_version]
      run_tests = options[:run_tests]
      backup_tempdir = options[:backup_tempdir]
      backup_s3_prefix = options[:backup_s3_prefix]
      aws_access_key = options[:aws_access_key]
      aws_secret_key = options[:aws_secret_key]

      rediscator_path = File.join(Dir.pwd, File.dirname(__FILE__), '..', '..')

      setup_properties = {
        :REDIS_VERSION => redis_version,
      }

      sudo! 'apt-get', :update
      package_install! *REQUIRED_PACKAGES

      unless user_exists?(REDIS_USER)
        sudo! *%W(adduser --disabled-login --gecos Redis,,, #{REDIS_USER})
      end
      setup_properties[:REDIS_USER] = REDIS_USER

      as REDIS_USER do
        inside "~#{REDIS_USER}" do
          run! *%w(mkdir -p opt)
          inside 'opt' do
            unless File.exists?('redis')
              run! :git, :clone, REDIS_REPO
            end
            inside 'redis' do
              unless git_branch_exists? redis_version
                run! :git, :checkout, '-b', redis_version, redis_version
              end
              run! :make
              run! :make, :test if run_tests
            end

            run! *%W(mkdir -p redis-#{redis_version})

            inside "redis-#{redis_version}" do
              run! *%w(mkdir -p bin etc log tmp)

              setup_properties[:REDIS_PATH] = Dir.pwd
              setup_properties[:REDIS_PASSWORD] = run!(*%w(pwgen --capitalize --numerals --symbols 16 1)).strip

              if File.exists?('tmp/redis.pid')
                File.open('tmp/redis.pid') {|pidfile| run! :kill, pidfile.read.strip }
                printf 'Waiting for Redis to die...'
                while File.exists?('tmp/redis.pid')
                  sleep 1
                  printf '.'
                end
                puts
              end

              %w(server cli).each do |thing|
                run! *%W(cp ../redis/src/redis-#{thing} bin)
              end

              substitution_variables = setup_properties.map {|name, value| ["[#{name}]", value] }

              config_substitutions = CONFIG_SUBSTITUTIONS.map do |pattern, replacement|
                [pattern, apply_substitutions(replacement, substitution_variables)]
              end

              default_conf = File.read('../redis/redis.conf')
              substituted_conf = apply_substitutions(default_conf, config_substitutions)

              create_file! 'etc/redis.conf', substituted_conf, :permissions => '640'

              run! *%W(#{setup_properties[:REDIS_PATH]}/bin/redis-server #{setup_properties[:REDIS_PATH]}/etc/redis.conf)
              run! 'bin/redis-cli', '-a', setup_properties[:REDIS_PASSWORD], :ping, :echo => false
            end
          end

          run! *%w(mkdir -p bin)
          run! *%W(cp #{rediscator_path}/bin/s3_gzbackup bin)

          sudo! :mkdir, '-p', backup_tempdir
          sudo! :chmod, 'a+rwxt', backup_tempdir

          create_file! '.s3cfg', <<-S3CFG, :permissions => '600'
[default]
access_key = #{aws_access_key}
secret_key = #{aws_secret_key}
          S3CFG

          backup_command = %W(
            ~#{REDIS_USER}/bin/s3_gzbackup
            --temp-dir='#{backup_tempdir}'
            #{setup_properties[:REDIS_PATH]}/dump.rdb
            '#{backup_s3_prefix}'
          ).join(' ')

          # make sure dump.rdb exists so the backup job doesn't fail
          run! "#{setup_properties[:REDIS_PATH]}/bin/redis-cli", '-a', setup_properties[:REDIS_PASSWORD], :save, :echo => false

          ensure_crontab_entry! backup_command, :hour => '03', :minute => '42'
        end
      end


      unless user_exists?(CLOUDWATCH_USER)
        sudo! *%W(adduser --disabled-login --gecos Amazon\ Cloudwatch\ monitor,,, #{CLOUDWATCH_USER})
      end
      setup_properties[:CLOUDWATCH_USER] = CLOUDWATCH_USER

      as CLOUDWATCH_USER do
        inside "~#{CLOUDWATCH_USER}" do
          home = Dir.pwd

          run! *%w(mkdir -p opt)
          cloudwatch_dir = nil
          inside 'opt' do
            if Dir.glob('CloudWatch-*/bin/mon-put-data').empty?
              run! :wget, '-q', CLOUDWATCH_TOOLS_URL unless File.exists? CLOUDWATCH_TOOLS_ZIP
              run! :unzip, CLOUDWATCH_TOOLS_ZIP
            end
            cloudwatch_dirs = Dir.glob('CloudWatch-*').select {|dir| File.directory? dir }
            case cloudwatch_dirs.size
            when 1; cloudwatch_dir = cloudwatch_dirs[0]
            when 0; raise 'Failed to install CloudWatch tools!'
            else; raise 'Multiple versions of CloudWatch tools installed; confused.'
            end
          end
          setup_properties[:CLOUDWATCH_TOOLS_PATH] = "#{home}/opt/#{cloudwatch_dir}"

          aws_credentials_path = "#{home}/.aws-credentials"
          create_file! aws_credentials_path, <<-CREDS, :permissions => '600'
AWSAccessKeyId=#{aws_access_key}
AWSSecretKey=#{aws_secret_key}
          CREDS

          run! *%w(mkdir -p bin)

          env_vars = [
            [:JAVA_HOME, OPENJDK_JAVA_HOME],
            [:AWS_CLOUDWATCH_HOME, setup_properties[:CLOUDWATCH_TOOLS_PATH]],
            [:PATH, %w($PATH $AWS_CLOUDWATCH_HOME/bin).join(':')],
            [:AWS_CREDENTIAL_FILE, aws_credentials_path],
          ]
          env_vars_script = (%w(#!/bin/sh) + env_vars.map do |var, value|
            "#{var}=#{value}; export #{var}"
          end).join("\n")
          env_vars_for_env = env_vars.map do |var, value|
            # run! doesn't expand $SHELL_VARIABLES, so we have to do it.
            expanded = value.
              gsub('$PATH', ENV['PATH']).
              gsub('$AWS_CLOUDWATCH_HOME', setup_properties[:CLOUDWATCH_TOOLS_PATH])
            "#{var}=#{expanded}"
          end

          cloudwatch_env_vars_path = "#{home}/bin/aws-cloudwatch-env-vars.sh"
          create_file! cloudwatch_env_vars_path, env_vars_script, :permissions => '+rwx'

          metric_script = <<-BASH
#!/bin/bash -e
export PATH=$PATH:$HOME/bin
. aws-cloudwatch-env-vars.sh

          BASH

          setup_properties[:CLOUDWATCH_NAMESPACE] = options[:cloudwatch_namespace]
          metric_dimensions = {
            :MachineName => options[:machine_name],
            :MachineRole => options[:machine_role],
          }
          if options[:ec2]
            instance_id = system!(*%w(curl -s http://169.254.169.254/latest/meta-data/instance-id)).strip
            metric_dimensions[:InstanceId] = instance_id
          end
          setup_properties[:CLOUDWATCH_DIMENSIONS] = metric_dimensions.map {|k, v| "#{k}=#{v}" }.join(',')

          [
             # friendly     metric-name      script               unit       minimum
            %w(Free\ RAM    FreeRAMPercent   free-ram-percent.sh  Percent    20),
            %w(Disk\ Space  DiskSpaceKBytes  free-disk-kbytes.sh  Kilobytes  2097152),
          ].each do |friendly, metric, script, unit, minimum|
            run! :cp, "#{rediscator_path}/bin/#{script}", :bin

            metric_script << %W(
              mon-put-data
              --metric-name '#{metric}'
              --namespace '#{options[:cloudwatch_namespace]}'
              --dimensions '#{setup_properties[:CLOUDWATCH_DIMENSIONS]}'
              --unit '#{unit}'
              --value "$(#{script})"
            ).join(' ') << "\n"

            # TODO alarm idempotence
            # (Seems not to create duplicate alarms, because CloudWatch seems
            # to dedupe them by name, but it does seem to re-send the initial
            # "everything is fine" notification email each time you run it.)
            alarm_options = %W(
              --alarm-name #{options[:machine_name]}:\ #{friendly}
              --alarm-description Alerts\ if\ #{options[:machine_role]}\ machine\ #{options[:machine_name]}\ is\ running\ low\ on\ #{friendly}.

              --namespace #{options[:cloudwatch_namespace]}
              --metric-name #{metric}
              --dimensions #{setup_properties[:CLOUDWATCH_DIMENSIONS]}

              --statistic Average
              --comparison-operator LessThanThreshold
              --threshold #{minimum}
              --unit #{unit}

              --period 60
              --evaluation-periods 5
            )
            if options[:sns_topic]
              alarm_options += %W(
                --actions-enabled true
                --ok-actions #{options[:sns_topic]}
                --alarm-actions #{options[:sns_topic]}
                --insufficient-data-actions #{options[:sns_topic]}
              )
            end

            run! *([:env] + env_vars_for_env + %W(#{setup_properties[:CLOUDWATCH_TOOLS_PATH]}/bin/mon-put-metric-alarm) + alarm_options)
          end

          create_file! 'bin/log-cloudwatch-metrics.sh', metric_script, :permissions => '+rwx'

          monitor_command = "$HOME/bin/log-cloudwatch-metrics.sh"
          ensure_crontab_entry! monitor_command, :minute => '*'
        end
      end

      puts "Properties:"
      setup_properties.each do |property, value|
        puts "\t#{property}:\t#{value}"
      end
    end
  end
end
