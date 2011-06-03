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
              run! :git, :checkout, '-b', REDIS_VERSION, REDIS_VERSION # TODO make this idempotent
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
                  new_conf.write(
                    default_conf.read.
                      sub(/^daemonize .*$/, 'daemonize yes').
                      sub(/^pidfile .*$/, "pidfile #{pwd}/tmp/redis.pid").
                      sub(/^loglevel .*$/, 'loglevel notice').
                      sub(/^logfile .*$/, "logfile #{pwd}/log/redis.log").
                      sub(/^dir .*$/, "dir #{pwd}"))
                end
              end
              run! *%w(cp /tmp/redis.conf etc)

              run! *%W(#{pwd}/bin/redis-server #{pwd}/etc/redis.conf)
              run! *%w(bin/redis-cli ping)
            end
          end
        end
      end
    end
  end
end
