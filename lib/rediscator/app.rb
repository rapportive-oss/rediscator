require 'thor'

require File.join(File.dirname(__FILE__), 'util')

module Rediscator
  class App < Thor
    namespace :rediscator

    include Thor::Actions
    include Util

    REQUIRED_PACKAGES = %w(git-core build-essential tcl8.5 pwgen)
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
    def setup
      redis_version = options[:redis_version]
      run_tests = options[:run_tests]

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

            redis_dir = "redis-#{redis_version}"
            run! :mkdir, '-p', *%w(bin etc log tmp).map {|dir| "#{redis_dir}/#{dir}" }
            inside redis_dir do
              pwd = Dir.pwd
              redis_password = run!(*%w(pwgen --capitalize --numerals --symbols 16 1)).strip
              redis_properties = {
                :REDIS_DIR => pwd,
                :REDIS_PASSWORD => redis_password,
              }

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
        end
      end
    end
  end
end
