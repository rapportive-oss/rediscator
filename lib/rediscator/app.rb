require 'thor'

require File.join(File.dirname(__FILE__), 'util')

module Rediscator
  class App < Thor
    namespace :rediscator

    include Thor::Actions
    include Util

    REQUIRED_PACKAGES = %w(git-core build-essential tcl8.5 pwgen s3cmd)
    REDIS_USER = 'redis'

    CONFIG_SUBSTITUTIONS = {
      /^daemonize .*$/ => 'daemonize yes',
      /^pidfile .*$/ => 'pidfile [REDIS_PATH]/tmp/redis.pid',
      /^loglevel .*$/ => 'loglevel notice',
      /^logfile .*$/ => 'logfile [REDIS_PATH]/log/redis.log',
      /^dir .*$/ => 'dir [REDIS_PATH]',
      /^# requirepass .*$/ => 'requirepass [REDIS_PASSWORD]',
    }

    desc 'setup', 'Set up Redis'
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
              run! *%w(git clone https://github.com/antirez/redis.git)
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

              File.open('../redis/redis.conf') do |default_conf|
                File.open('/tmp/redis.conf', 'w') do |new_conf|
                  substitution_variables = setup_properties.map {|name, value| ["[#{name}]", value] }

                  config_substitutions = CONFIG_SUBSTITUTIONS.map do |pattern, replacement|
                    [pattern, apply_substitutions(replacement, substitution_variables)]
                  end

                  substituted_conf = apply_substitutions(default_conf.read, config_substitutions)

                  new_conf.write(substituted_conf)
                  new_conf.flush

                  run! *%w(cp /tmp/redis.conf etc)
                  run! *%w(chmod 640 etc/redis.conf)

                  File.unlink('/tmp/redis.conf')
                end
              end

              run! *%W(#{setup_properties[:REDIS_PATH]}/bin/redis-server #{setup_properties[:REDIS_PATH]}/etc/redis.conf)
              run! *%W(bin/redis-cli -a #{setup_properties[:REDIS_PASSWORD]} ping)
            end
          end

          run! *%w(mkdir -p bin)
          run! *%W(cp #{rediscator_path}/bin/s3_gzbackup bin)

          sudo! :mkdir, '-p', backup_tempdir
          sudo! :chmod, 'a+rwxt', backup_tempdir

          s3cfg = <<-S3CFG
[default]
access_key = #{aws_access_key}
secret_key = #{aws_secret_key}
          S3CFG
          File.open('/tmp/.s3cfg', 'w') do |new_s3cfg|
            new_s3cfg.write(s3cfg)
            new_s3cfg.flush
            run! *%w(cp /tmp/.s3cfg .)
            run! *%w(chmod 600 .s3cfg)
            File.unlink('/tmp/.s3cfg')
          end

          backup_command = %W(
            ~#{REDIS_USER}/bin/s3_gzbackup
            --temp-dir='#{backup_tempdir}'
            #{setup_properties[:REDIS_PATH]}/dump.rdb
            '#{backup_s3_prefix}'
          ).join(' ')

          ensure_crontab_entry! backup_command, :hour => '03', :minute => '42'
        end
      end

      puts "Properties:"
      setup_properties.each do |property, value|
        puts "\t#{property}:\t#{value}"
      end
    end
  end
end
