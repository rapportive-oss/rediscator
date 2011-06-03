require 'open4'

module Rediscator
  module Util
    class ShellError < StandardError; end

    def system!(*args)
      command = args.join(' ')
      puts command

      out = ''
      err = ''
      args = args.map(&:to_s) + [{:stdout => out, :stderr => err}]
      open4.spawn(*args)
      puts out
      out
    rescue Open4::SpawnError => e
      raise ShellError, "command #{command} failed with status #{e.exitstatus}: #{err}"
    rescue SystemCallError => e
      raise ShellError, "command #{command} failed: #{e}"
    end

    def sudo!(*args)
      system! :sudo, *args
    end

    def run!(*args)
      if @user.nil?
        system! *args
      else
        run_as! @user, *args
      end
    end

    def run_as!(user, *args)
      sudo! '-u', user, *args
    end

    def as(user)
      old_user = @user
      @user = user
      yield
    ensure
      @user = old_user
    end

    def package_install!(*packages)
      sudo! 'apt-get', 'install', '-y', *packages
    end

    def user_exists?(user)
      File.open('/etc/passwd') do |passwd|
        passwd.any? {|line| user.to_s == line.split(':')[0] }
      end
    end

    def apply_substitutions(string, substitutions)
      substitutions.inject(string) do |str, (pattern, replacement)|
        str.gsub(pattern, replacement)
      end
    end
  end
end
