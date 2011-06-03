require 'thor'

require File.join(File.dirname(__FILE__), 'util')

module Rediscator
  class App < Thor
    namespace :rediscator

    include Thor::Actions
    include Util

    REQUIRED_PACKAGES = %w(git-core build-essential tcl8.5)
    REDIS_USER = 'redis'
    REDIS_VERSION = '2.2.8'
    RUN_REDIS_TESTS = false

    REDIS_SUPER_SECRET_PASSWORD = 'super_secret_01'

    CONFIG_SUBSTITUTIONS = {
      /^daemonize .*$/ => 'daemonize yes',
      /^pidfile .*$/ => 'pidfile [REDIS_DIR]/tmp/redis.pid',
      /^loglevel .*$/ => 'loglevel notice',
      /^logfile .*$/ => 'logfile [REDIS_DIR]/log/redis.log',
      /^dir .*$/ => 'dir [REDIS_DIR]',
      /^# requirepass .*$/ => 'requirepass [REDIS_PASSWORD]',
    }

    desc 'setup', 'Set up Redis'
    def setup
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
              unless git_branch_exists? REDIS_VERSION
                run! :git, :checkout, '-b', REDIS_VERSION, REDIS_VERSION
              end
              run! :make
              run! :make, :test if RUN_REDIS_TESTS
            end

            redis_dir = "redis-#{REDIS_VERSION}"
            run! :mkdir, '-p', *%w(bin etc log tmp).map {|dir| "#{redis_dir}/#{dir}" }
            inside redis_dir do
              pwd = Dir.pwd

              %w(server cli).each do |thing|
                run! *%W(cp ../redis/src/redis-#{thing} bin)
              end
              File.open('../redis/redis.conf') do |default_conf|
                File.open('/tmp/redis.conf', 'w') do |new_conf|
                  substitution_variables = {
                    :REDIS_DIR => pwd,
                    :REDIS_PASSWORD => REDIS_SUPER_SECRET_PASSWORD,
                  }.map {|name, value| ["[#{name}]", value] }

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
              run! *%W(bin/redis-cli -a #{REDIS_SUPER_SECRET_PASSWORD} ping)
            end
          end
        end
      end
    end
  end
end