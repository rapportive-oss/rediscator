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
      /^pidfile .*$/ => 'pidfile [REDIS_DIR]/tmp/redis.pid',
      /^loglevel .*$/ => 'loglevel notice',
      /^logfile .*$/ => 'logfile [REDIS_DIR]/log/redis.log',
      /^dir .*$/ => 'dir [REDIS_DIR]',
      /^# requirepass .*$/ => 'requirepass [REDIS_PASSWORD]',
    }

    desc 'setup', 'Set up Redis'
    method_option :redis_version, :required => true, :desc => "Version of Redis to install"
    method_option :run_tests, :default => false, :type => :boolean, :desc => "Whether to run the Redis test suite"
    method_option :backup_tempdir, :default => '/tmp', :desc => "Temporary directory for daily backups"
    method_option :backup_s3_prefix, :required => true, :desc => "S3 bucket and prefix for daily backups, e.g. s3://backups/redis"
    def setup
      redis_version = options[:redis_version]
      run_tests = options[:run_tests]
      backup_tempdir = options[:backup_tempdir]
      backup_s3_prefix = options[:backup_s3_prefix]

      redis_dir = "redis-#{redis_version}"
      redis_path = "~#{REDIS_USER}/opt/#{redis_dir}"
      rediscator_path = File.join(Dir.pwd, File.dirname(__FILE__), '..', '..')

      package_install! *REQUIRED_PACKAGES

      unless user_exists?(REDIS_USER)
        sudo! *%W(adduser --disabled-login --gecos Redis,,, #{REDIS_USER})
      end

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

            run! :mkdir, '-p', *%w(bin etc log tmp).map {|dir| "#{redis_dir}/#{dir}" }
            inside redis_dir do
              pwd = Dir.pwd
              redis_password = run!(*%w(pwgen --capitalize --numerals --symbols 16 1)).strip
              redis_properties = {
                :REDIS_DIR => pwd,
                :REDIS_PASSWORD => redis_password,
              }

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
                  substitution_variables = redis_properties.map {|name, value| ["[#{name}]", value] }

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

              run! *%W(#{pwd}/bin/redis-server #{pwd}/etc/redis.conf)
              run! *%W(bin/redis-cli -a #{redis_password} ping)

              puts "Properties:"
              redis_properties.each do |property, value|
                puts "\t#{property}:\t#{value}"
              end
            end
          end

          run! *%w(mkdir -p bin)
          run! *%W(cp #{rediscator_path}/bin/s3_gzbackup bin)

          sudo! :mkdir, '-p', backup_tempdir
          sudo! :chmod, 'a+rwxt', backup_tempdir

          backup_command = %W(
            ~#{REDIS_USER}/bin/s3_gzbackup
            --temp-dir='#{backup_tempdir}'
            #{redis_path}/dump.rdb
            '#{backup_s3_prefix}'
          ).join(' ')

          crontab_entry = <<-CRONTAB
# m h  dom mon dow command
42  03 *   *   *   #{backup_command}
          CRONTAB

          old_crontab = begin
                          run! :crontab, '-l'
                        rescue ShellError => se
                          if se.message =~ /\bno crontab for #{REDIS_USER}\b/
                            ''
                          else
                            raise
                          end
                        end
          if old_crontab.grep(/#{Regexp.escape backup_command}$/).empty?
            new_crontab = old_crontab + "\n" + crontab_entry
            run! :crontab, '-', :stdin => new_crontab
          end
        end
      end
    end
  end
end
