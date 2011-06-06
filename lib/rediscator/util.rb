require 'open4'

module Rediscator
  module Util
    class ShellError < StandardError; end

    def system!(*args)
      out = ''
      err = ''
      default_opts = {:stdout => out, :stderr => err}

      opts = if args.last.is_a? Hash
               args.pop
             else
               {}
             end

      assert_valid_keys! opts, :stdin

      command = args.join(' ')
      puts command

      args = args.map(&:to_s) + [default_opts.merge(opts)]
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

    def git_branch_exists?(branch)
      !run!(:git, :branch).grep(/\b#{Regexp.escape branch}\b/).empty?
    end

    def apply_substitutions(string, substitutions)
      substitutions.inject(string) do |str, (pattern, replacement)|
        str.gsub(pattern, replacement)
      end
    end

    def ensure_crontab_entry!(command, schedule_opts)
      entry = crontab_entry(command, schedule_opts)

      old_crontab = begin
                      run! :crontab, '-l'
                    rescue ShellError => se
                      if se.message =~ /\bno crontab for\b/
                        ''
                      else
                        raise
                      end
                    end
      if old_crontab.grep(/\s+#{Regexp.escape command}$/).empty?
        new_crontab = old_crontab + "\n\n" + entry
        run! :crontab, '-', :stdin => new_crontab
        new_crontab
      else
        old_crontab
      end
    end

    # To run a command every minute, specify :minute => '*' (that would make a
    # surprising default!).
    def crontab_entry(command, schedule_opts)
      schedule_parts = [
        [:m, :minute],
        [:h, :hour],
        [:dom, :day],
        [:mon, :month],
        [:dow, :day_of_week],
      ]
      assert_valid_keys! schedule_opts, *schedule_parts.flatten
      raise ArgumentError, "must specify a schedule" if schedule_opts.empty?

      labels = schedule_parts.map(&:first) + ['command']
      header = '# ' + labels.join("\t")
      schedule = schedule_parts.map do |label, friendly|
        part = schedule_opts.values_at(label, friendly).compact
        case part.size
        when 1; part[0].to_s
        when 2; raise ArgumentError, "can't specify both :#{label} and :#{friendly}"
        else; '*'
        end
      end
      entry = (schedule + [command]).join("\t")

      header + "\n" + entry + "\n"
      # stick a newline on the end because cron is picky about such things
    end

    def assert_valid_keys!(opts, *keys)
      invalid_opts = opts.keys - keys
      raise ArgumentError, "unknown options: #{invalid_opts.map(&:inspect).join(' ')}", caller unless invalid_opts.empty?
    end
  end
end
