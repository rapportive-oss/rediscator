module Rediscator
  module Util
    class ShellError < StandardError; end

    def system!(*args)
      puts args.join(' ')
      system(*args.map(&:to_s)) or raise ShellError, "command #{args.join(' ').inspect} failed!"
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
  end
end
