require 'date'

require 'thor'
require 'right_aws'

require File.join(File.dirname(__FILE__), 'util')

module Rediscator
  class App < Thor
    namespace :rediscator

    include Thor::Actions
    include Util

    class_option :machine_name, :default => `hostname`.strip, :desc => "Name identifying this Redis machine"

    REQUIRED_PACKAGES = %w(
      build-essential
      pwgen
      s3cmd
      openjdk-6-jre-headless
      unzip
      postfix
    )

    OPENJDK_JAVA_HOME = '/usr/lib/jvm/java-6-openjdk'

    REDIS_USER = 'redis'
    REDIS_LOG = '/var/log/redis.log'

    CLOUDWATCH_USER = 'cloudwatch'
    CLOUDWATCH_TOOLS_ZIP = 'CloudWatch-2010-08-01.zip'
    CLOUDWATCH_TOOLS_URL = "http://ec2-downloads.s3.amazonaws.com/#{CLOUDWATCH_TOOLS_ZIP}"

    REDIS_CONFIG_SUBSTITUTIONS = {
      /^daemonize .*$/ => 'daemonize no', # since we're using upstart to run it
      /^pidfile .*$/ => 'pidfile [REDIS_PATH]/tmp/redis.pid',
      /^loglevel .*$/ => 'loglevel notice',
      /^logfile .*$/ => 'logfile stdout',
      /^# syslog-enabled .*$/ => 'syslog-enabled yes',
      /^# syslog-ident .*$/ => "syslog-ident redis",
      /^dir .*$/ => 'dir [REDIS_PATH]',
      /^# requirepass .*$/ => 'requirepass [REDIS_PASSWORD]',
      /^# maxmemory .*$/ => 'maxmemory [REDIS_MAX_MEMORY]',
      /^# maxmemory-policy .*$/ => 'maxmemory-policy [REDIS_MAX_MEMORY_POLICY]',
    }


    def initialize(*args)
      super
      @setup_properties = {
        :MACHINE_NAME => options[:machine_name],
      }
      @rediscator_path = File.join(Dir.pwd, File.dirname(__FILE__), '..', '..')
    end


    desc 'setup', 'Set up Redis'
    method_option :admin_email, :required => true, :desc => "Email address to receive admin messages"
    method_option :machine_role, :default => 'redis', :desc => "Description of this machine's role"
    method_option :ec2, :default => false, :type => :boolean, :desc => "Whether this instance is on EC2"
    method_option :remote_syslog, :desc => "Remote syslog endpoint to send all logs to"
    method_option :cloudwatch_namespace, :default => `hostname`.strip, :desc => "Namespace for CloudWatch metrics"
    method_option :sns_topic, :desc => "Simple Notification Service topic ARN for alarm notifications"
    method_option :redis_version, :default => 'stable', :desc => "Version of Redis to install"
    method_option :redis_max_memory, :required => true, :desc => "Max size of Redis dataset"
    method_option :redis_max_memory_policy, :required => true, :desc => "What Redis should do when dataset size reaches max"
    method_option :redis_run_tests, :default => false, :type => :boolean, :desc => "Whether to run the Redis test suite"
    method_option :backup_tempdir, :default => '/tmp', :desc => "Temporary directory for daily backups"
    method_option :backup_s3_prefix, :required => true, :desc => "S3 bucket and prefix for daily backups, e.g. s3://backups/redis"
    method_option :aws_access_key, :required => true, :desc => "AWS access key ID for creating IAM user"
    method_option :aws_secret_key, :required => true, :desc => "AWS secret access key for creating IAM user"
    method_option :aws_iam_group, :desc => "AWS IAM group for backup and monitoring"
    method_option :iam_delete_oldest_key, :type => :boolean, :default => false, :desc => "If the IAM user already exists and already has the maximum allowed number of access keys, whether to delete the oldest key to make room."
    def setup
      backup_tempdir = options[:backup_tempdir]
      backup_s3_prefix = options[:backup_s3_prefix]

      install_prereqs :admin_email => options[:admin_email], :redis_run_tests => options[:redis_run_tests]

      iam_access_key = generate_access_key :username => options[:machine_name],
        :group => options[:aws_iam_group],
        :delete_oldest_key => options[:iam_delete_oldest_key],
        :access_key_id => options[:aws_access_key],
        :secret_key => options[:aws_secret_key]
      props[:IAM_USERNAME], aws_access_key, aws_secret_key = iam_access_key.values_at(:user_name, :access_key_id, :secret_access_key)

      install_crash_warning

      setup_remote_syslog(options[:remote_syslog]) if options[:remote_syslog]
      setup_redis_log
      sudo! *%w(restart rsyslog)

      props[:REDIS_USER] = REDIS_USER
      create_user props[:REDIS_USER]

      props.merge!({
        :REDIS_VERSION => options[:redis_version],
        :REDIS_MAX_MEMORY => options[:redis_max_memory],
        :REDIS_MAX_MEMORY_POLICY => options[:redis_max_memory_policy],
      })

      install_redis :version => props[:REDIS_VERSION],
        :run_tests => options[:redis_run_tests]

      configure_redis

      sudo! *%w(start redis)

      sleep 1
      run_as! props[:REDIS_USER], "#{props[:REDIS_PATH]}/bin/redis-cli", '-a', props[:REDIS_PASSWORD], :ping, :echo => false

      install_authed_redis_cli
      detect_redis_version

      as props[:REDIS_USER] do
        ensure_crontab_entry! 'bin/authed-redis-cli PING | { grep -v PONG || true; }', :minute => '*'

        inside "~#{props[:REDIS_USER]}" do
          run! *%W(cp #{supplied 'bin/s3_gzbackup'} bin)

          sudo! :mkdir, '-p', backup_tempdir
          sudo! :chmod, 'a+rwxt', backup_tempdir

          create_file! '.s3cfg', <<-S3CFG, :permissions => '600'
[default]
access_key = #{aws_access_key}
secret_key = #{aws_secret_key}
          S3CFG

          backup_command = %W(
            ~#{props[:REDIS_USER]}/bin/s3_gzbackup
            --temp-dir='#{backup_tempdir}'
            #{props[:REDIS_PATH]}/dump.rdb
            '#{backup_s3_prefix}'
          ).join(' ')

          # make sure dump.rdb exists so the backup job doesn't fail
          run! "#{props[:REDIS_PATH]}/bin/redis-cli", '-a', props[:REDIS_PASSWORD], :save, :echo => false

          ensure_crontab_entry! backup_command, :hour => '03', :minute => '42'
        end
      end


      props[:CLOUDWATCH_USER] = CLOUDWATCH_USER
      create_user props[:CLOUDWATCH_USER], :description => 'Amazon Cloudwatch monitor'


      as props[:CLOUDWATCH_USER] do
        inside "~#{props[:CLOUDWATCH_USER]}" do
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
          props[:CLOUDWATCH_TOOLS_PATH] = "#{home}/opt/#{cloudwatch_dir}"

          aws_credentials_path = "#{home}/.aws-credentials"
          create_file! aws_credentials_path, <<-CREDS, :permissions => '600'
AWSAccessKeyId=#{aws_access_key}
AWSSecretKey=#{aws_secret_key}
          CREDS

          ensure_sudoers_entry! :who => props[:CLOUDWATCH_USER],
                                :as_who => props[:REDIS_USER],
                                :nopasswd => true,
                                :commands => ['INFO', 'CONFIG GET*'].map {|command| "/home/#{props[:REDIS_USER]}/bin/authed-redis-cli #{command}" },
                                :comment => "Allow #{props[:CLOUDWATCH_USER]} to gather Redis metrics, but not do anything else to Redis"

          run! *%w(mkdir -p bin)

          env_vars = [
            [:JAVA_HOME, OPENJDK_JAVA_HOME],
            [:AWS_CLOUDWATCH_HOME, props[:CLOUDWATCH_TOOLS_PATH]],
            [:PATH, %w($PATH $AWS_CLOUDWATCH_HOME/bin).join(':')],
            [:AWS_CREDENTIAL_FILE, aws_credentials_path],
          ]
          env_vars_script = (%w(#!/bin/sh) + env_vars.map do |var, value|
            "#{var}=#{value}; export #{var}"
          end).join("\n")
          setup_time_env_vars = env_vars.map do |var, value|
            # run! doesn't expand $SHELL_VARIABLES, so we have to do it.
            expanded = value.
              gsub('$PATH', ENV['PATH']).
              gsub('$AWS_CLOUDWATCH_HOME', props[:CLOUDWATCH_TOOLS_PATH])
            [var, expanded]
          end

          cloudwatch_env_vars_path = "#{home}/bin/aws-cloudwatch-env-vars.sh"
          create_file! cloudwatch_env_vars_path, env_vars_script, :permissions => '+rwx'

          metric_script = <<-BASH
#!/bin/bash -e
export PATH=$PATH:$HOME/bin
. aws-cloudwatch-env-vars.sh

          BASH

          props[:CLOUDWATCH_NAMESPACE] = options[:cloudwatch_namespace]
          custom_metric_dimensions = {
            :MachineName => options[:machine_name],
            :MachineRole => options[:machine_role],
          }
          builtin_metric_dimensions = {}
          if options[:ec2]
            instance_id = system!(*%w(curl -s http://169.254.169.254/latest/meta-data/instance-id)).strip
            custom_metric_dimensions[:InstanceId] = builtin_metric_dimensions[:InstanceId] = instance_id
          end
          props[:CLOUDWATCH_DIMENSIONS] = cloudwatch_dimensions(custom_metric_dimensions)

          shared_alarm_options = {
            :cloudwatch_tools_path => props[:CLOUDWATCH_TOOLS_PATH],
            :env_vars => setup_time_env_vars,

            :dimensions => custom_metric_dimensions,
          }
          if options[:sns_topic]
            topic = options[:sns_topic]
            props[:SNS_TOPIC] = topic
            shared_alarm_options.merge!({
              :actions_enabled => true,
              :ok_actions => topic,
              :alarm_actions => topic,
              :insufficient_data_actions => topic,
            })
          else
            props[:SNS_TOPIC] = "<WARNING: No SNS topic specified.  You will not get notified of alarm states.>"
          end

          metrics = [
            # friendly                metric-name               script                  script-args                  unit       check
            ['Free RAM',              :FreeRAMPercent,          'free-ram-percent.sh',  [],                          :Percent,  [:<,      20]],
            ['Free Disk',             :FreeDiskPercent,         'free-disk-percent.sh', [],                          :Percent,  [:<,      20]],
            ['Load Average (1min)',   :LoadAvg1Min,             'load-avg.sh',          [1],                         :Count,    nil          ],
            ['Load Average (15min)',  :LoadAvg15Min,            'load-avg.sh',          [3],                         :Count,    [:>,     1.0]],
            ['Redis Blocked Clients', :RedisBlockedClients,     'redis-metric.sh',      %w(blocked_clients),         :Count,    [:>,       5]],
            ['Redis Evicted Keys',    :RedisEvictedKeys,        'redis-metric.sh',      %w(evicted_keys),            :Count,    nil          ],
            ['Redis Used Memory',     :RedisUsedMemory,         'redis-metric.sh',      %w(used_memory),             :Bytes,    nil          ],
            ['Redis Unsaved Changes', :RedisUnsavedChanges,     'redis-metric.sh',      %w(changes_since_last_save), :Count,    [:>, 300_000]],
            ['Redis % of Max',        :RedisFullness,           'redis-fullness.sh',    [],                          :Percent,  nil          ],
          ]

          if options[:ec2]
            metrics << ['CPU Usage', 'AWS/EC2:CPUUtilization',  nil,                    [],                  :Percent,  [:>,  90]]
          end

          metric_scripts = metrics.map {|_, _, script, _, _, _| supplied("bin/#{script}") if script }.compact.uniq
          run! :cp, *(metric_scripts + [:bin])
          metrics.each do |friendly, metric, script, args, unit, (comparison, threshold)|
            namespace_or_metric, metric_or_nil = metric.to_s.split(':', 2)
            if metric_or_nil
              namespace = namespace_or_metric
              metric = metric_or_nil
              dimensions = builtin_metric_dimensions
            else
              namespace = options[:cloudwatch_namespace]
              metric = namespace_or_metric
              dimensions = custom_metric_dimensions
            end

            if script
              metric_script << "#{metric}=$(#{script} #{args.map {|arg| "'#{arg}'" }.join(' ')})\n"
              metric_script << %W(
                mon-put-data
                --metric-name '#{metric}'
                --namespace '#{namespace}'
                --dimensions '#{cloudwatch_dimensions(dimensions)}'
                --unit '#{unit}'
                --value "$#{metric}"
              ).join(' ') << "\n"
            end

            if comparison
              symptom = case comparison
                        when :>, :>=; 'high'
                        when :<, :<=; 'low'
                        end
              alarm_options = shared_alarm_options.merge({
                :alarm_name => "#{options[:machine_name]}: #{friendly}",
                :alarm_description => "Alerts if #{options[:machine_role]} machine #{options[:machine_name]} has #{symptom} #{friendly}.",

                :namespace => namespace,
                :metric_name => metric,
                :dimensions => dimensions,

                :comparison_operator => comparison,
                :threshold => threshold,
                :unit => unit,
              })

              setup_cloudwatch_alarm! alarm_options
            end
          end

          create_file! 'bin/log-cloudwatch-metrics.sh', metric_script, :permissions => '+rwx'

          monitor_command = "$HOME/bin/log-cloudwatch-metrics.sh"
          ensure_crontab_entry! monitor_command, :minute => '*/2'
        end
      end

      puts "Properties:"
      props.each do |property, value|
        puts "\t#{property}:\t#{value}"
      end
    end


    private
    def install_prereqs(opts)
      unless props[:MACHINE_NAME] =~ /\w+\.\w+$/
        raise ArgumentError, "--machine-name should be a FQDN or Postfix will break :("
      end

      props[:ADMIN_EMAIL] = opts[:admin_email] or raise ArgumentError, 'must specify :admin_email'

      sudo! 'apt-get', :update

      sudo! 'debconf-set-selections', :stdin => from_template('etc/postfix.debconf')

      packages = REQUIRED_PACKAGES
      packages << 'tcl8.5' if opts[:redis_run_tests]

      package_install! *packages
    end


    # Generate AWS access credentials for regular backup and monitoring jobs
    def generate_access_key(opts)
      access_key_id = opts[:access_key_id] or raise ArgumentError, 'must specify :access_key_id'
      secret_key = opts[:secret_key] or raise ArgumentError, 'must specify :secret_key'
      iam = RightAws::IamInterface.new(access_key_id, secret_key)

      iam_username = opts[:username] or raise ArgumentError, 'must specify :username'

      begin
        iam_user = iam.create_user(iam_username)
      rescue RightAws::AwsError => e
        raise unless e.message =~ /EntityAlreadyExists/
      end

      iam.add_user_to_group(iam_username, opts[:group]) if opts[:group]

      iam_access_key = nil
      while !iam_access_key
        begin
          iam_access_key = iam.create_access_key(:user_name => iam_username)
        rescue RightAws::AwsError => e
          raise unless e.message =~ /LimitExceeded.*AccessKeysPerUser/

          if opts[:delete_oldest_key]
            keys = iam.list_access_keys(:user_name => iam_username)

            case keys.length
            when 1; raise "IAM user #{iam_username} only has one access key, don't want to delete it.  Use https://console.aws.amazon.com/iam if you really want to do that."
            when 0; raise "IAM user #{iam_username} has no access keys; confused.  Try https://console.aws.amazon.com/iam to diagnose."
            end

            oldest = keys.sort do |key1, key2|
              if key1[:status] == 'Inactive'
                -1
              elsif key2[:status] == 'Inactive'
                1
              else
                DateTime.parse(key1[:create_date]) <=> DateTime.parse(key2[:create_date])
              end
            end.first

            iam.delete_access_key(oldest[:access_key_id], :user_name => iam_username)
          else
            raise "IAM user #{iam_username} already has max access keys! Try --iam-delete-oldest-key option."
          end
        end
      end

      iam_access_key
    end


    # Set up an Upstart rule to email the admin if Redis crashes and cannot be restarted.
    def install_crash_warning
      as :root do
        create_file! '/etc/init/redis-warn-stopped.conf', from_template('etc/redis-warn-stopped.upstart')
      end
    end


    # Configure syslog to send logs to a remote syslog server
    def setup_remote_syslog(endpoint)
      as :root do
        create_file! '/etc/rsyslog.d/60-remote-syslog.conf', <<-RSYSLOG
*.*                                     @#{endpoint}
        RSYSLOG
      end
    end


    # Set up Redis logs to go to REDIS_LOG with log rotation
    def setup_redis_log
      as :root do
        create_file! '/etc/rsyslog.d/99-redis.conf', <<-RSYSLOG
:programname, isequal, "redis"          #{REDIS_LOG}
        RSYSLOG

        create_file! '/etc/logrotate.d/redis', <<-LOGROTATE
#{REDIS_LOG} {
        weekly
        missingok
        rotate 20
        compress
        delaycompress
        notifempty
        postrotate
          reload rsyslog >/dev/null 2>&1 || true
        endscript
}
        LOGROTATE
      end

      props[:REDIS_LOG] = REDIS_LOG
    end


    # Download and compile the desired version of Redis
    def install_redis(opts)
      version = opts[:version] || 'stable'

      redis_path = nil

      as props[:REDIS_USER] do
        inside "~#{props[:REDIS_USER]}" do
          run! *%w(mkdir -p opt)

          inside 'opt' do
            unless File.exists?("redis-#{version}")
              tarball_url = if 'stable' == version.downcase
                              'http://download.redis.io/redis-stable.tar.gz'
                            else
                              "http://redis.googlecode.com/files/redis-#{version}.tar.gz"
                            end
              run! :wget, tarball_url
              run! :tar, 'zxf', "redis-#{version}.tar.gz"
            end

            inside "redis-#{version}" do
              run! :make

              if opts[:run_tests]
                package_install! 'tcl8.5'
                run! :make, :test
              end

              redis_path = Dir.pwd
            end
          end
        end
      end

      props[:REDIS_PATH] = redis_path
    end


    def configure_redis
      as props[:REDIS_USER] do
        inside props[:REDIS_PATH] do
          run! *%w(mkdir -p bin etc tmp)

          props[:REDIS_PASSWORD] = run!(*%w(pwgen --capitalize --numerals --symbols 16 1)).strip

          as :root do
            create_file! '/etc/init/redis.conf', from_template('etc/redis.upstart')

            # If the Redis binaries are already in place and Redis is
            # running, we'll get an error trying to overwrite the binaries,
            # so stop it running first.
            if run!(*%w(status redis)).strip =~ %r{ start/running\b}
              run! *%w(stop redis)
            end
          end

          %w(server cli).each do |thing|
            run! *%W(cp src/redis-#{thing} bin)
          end

          config_substitutions = REDIS_CONFIG_SUBSTITUTIONS.map do |pattern, replacement|
            [pattern, apply_substitutions(replacement, props)]
          end

          default_conf = File.read('redis.conf')
          substituted_conf = apply_substitutions(default_conf, config_substitutions)

          create_file! 'etc/redis.conf', substituted_conf, :permissions => '640'
        end
      end
    end


    def install_authed_redis_cli
      as props[:REDIS_USER] do
        inside "~#{props[:REDIS_USER]}" do
          run! *%w(mkdir -p bin)

          create_file! 'bin/redispw', <<-SH, :permissions => '755'
#!/bin/sh -e
grep ^requirepass #{props[:REDIS_PATH]}/etc/redis.conf | cut -d' ' -f2
          SH

          create_file! 'bin/authed-redis-cli', <<-SH, :permissions => '755'
#!/bin/sh -e
exec #{props[:REDIS_PATH]}/bin/redis-cli -a "$(~#{props[:REDIS_USER]}/bin/redispw)" "$@"
          SH
        end
      end
    end


    def detect_redis_version
      props[:REDIS_VERSION] = run_as!(props[:REDIS_USER], "/home/#{props[:REDIS_USER]}/bin/authed-redis-cli", :info).
        split("\n").
        map {|line| line.split(':', 2) }.
        detect {|property, value| property == 'redis_version' }[1]
    end


    def props
      @setup_properties
    end

    def supplied(*args)
      File.join(@rediscator_path, *args)
    end

    def from_template(template_name)
      template = File.read(supplied(template_name))
      apply_substitutions(template, @setup_properties)
    end

    # Create a user with login disabled and mail going to root
    def create_user(username, opts = {})
      description = opts[:description] || username.sub(/[a-z]/) {|initial| initial.upcase }
      unless user_exists?(username)
        sudo! *%W(adduser --disabled-login --gecos #{description},,, #{username})
      end

      home = nil
      as username do
        inside "~#{username}" do
          create_file! '.forward', 'root'
          home = Dir.pwd
        end
      end

      {
        :username => username,
        :home => home,
      }
    end
  end
end
