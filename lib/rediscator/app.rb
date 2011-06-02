require 'thor'

require File.join(File.dirname(__FILE__), 'util')

module Rediscator
  class App < Thor
    namespace :rediscator

    include Thor::Actions
    include Util

    desc 'setup', 'Set up Redis'
    def setup
      package_install! *%w(git-core build-essential tcl8.5)

      unless user_exists?(:redis)
        sudo! *%w(adduser --disabled-login --gecos Redis,,, redis)
      end

      as :redis do
        inside '~redis' do
          run! *%w(mkdir -p opt)
          inside 'opt' do
            unless File.exists?('redis')
              run! *%w(git clone https://github.com/antirez/redis.git)
            end
            inside 'redis' do
              run! *%w(git checkout -b 2.2.8 2.2.8) # TODO make this idempotent
              run! :make
              run! :make, :test if false # TODO
            end

            run! :mkdir, '-p', *%w(bin etc log tmp).map {|dir| "redis-2.2.8/#{dir}" }
            inside 'redis-2.2.8' do
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
