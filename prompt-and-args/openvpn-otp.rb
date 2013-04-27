#!/usr/bin/ruby1.9.1

require 'optparse'
require 'optparse/time'
require 'ostruct'
require 'pp'
require 'set'
require 'fileutils'
require 'logger'
require 'timeout'

begin
  require "highline/import"
  require "file-tail"
  require "sys/proctable"
  include Sys
rescue LoadError => e
  raise unless e.message =~ /(highline|file-tail|sys-proctable)/
  puts "#{e} is a gem dependencies and must be installed" 
  exit 1
end

if ! RUBY_VERSION =~ /1.9/
  puts "This script needs to run under ruby 1.9.x, and you're running under #{RUBY_VERSION}"
  exit 1
end


##
### Parse options:
##

class OptparseOpenVPN

  def self.parse(env, args)
    
    options = {}
   
    opts = OptionParser.new do |opts|
      options[:banner] = "Usage: backup.rb [options]"

      # username
      options[:username] = nil
      opts.on('-u', '--username USERNAME', 'Unix/PAM username') do |u|
        options[:username] = u
      end

      # password
      options[:password] = nil
      opts.on('-p', '--password PASSWORD', 'Password for USERNAME') do |p|
        options[:password] = p
      end

      # OTP
      options[:otp] = nil
      opts.on('-o', '--otp ONETIMEPASSWORD', 'Onetime password') do |o|
        options[:otp] = o
      end

      # Config file:
      options[:config] = env
      opts.on('-c', '--config config_file', 'OpenVPN config file') do |c|
        options[:config] = c
      end

      # loglevel
      options[:loglevel] = 'INFO'
      opts.on("-l", "--loglevel level", 'Change Logging level') do |l|
        options[:loglevel] = l
      end

      # verbosity boolean switch.
      options[:verbose] = false
      opts.on("-v", "--[no-]verbose", "Run verbosely") do |v|
        options[:verbose] = v
      end

      # interactive
      options[:interactive] = false
      opts.on("-i", "--[no-]interactive", "Run Interactively") do |i|
        options[:interactive] = i
      end

      # disconnect
      options[:disconnect] = false
      opts.on("-d", "--[no-]disconnect", "Run disconnectly") do |i|
        options[:disconnect] = i
      end

      # timeout:
      options[:timeout] = '60'
      opts.on("-t", "--timeout [seconds]", "Set timeout - defaults to 60 secs") do |t|
        options[:timeout] = t
      end

      opts.separator ""
      opts.separator "Common options:"

      # No argument, shows at tail.  This will print an options summary.
      # Try it and see!
      opts.on_tail("-h", "--help", "Show this message") do
        puts opts
        exit
      end

      # Another typical switch to print the version.
      opts.on_tail("--version", "Show version") do
        puts OptionParser::Version.join('.')
        exit
      end
    end

    opts.parse!(args)
    options

  end  # parse()

end  # class OptparseOpenVPN

##
### Prompt for options - run interactively
##

class OptpromptOpenVPN

  def self.opt_prompt(verbose = false, env, args)

    puts "* "*10
    puts "* * OpenVPN client connection using YubiKey OTP"
    puts "* "*10
    
    options = {}

    # username
    options[:username] = ask("Username: ") { |q| q.default = Etc.getlogin }

    # password
    options[:password] = ask("Password: ") { |q| q.echo = '*' }

    # OTP
    options[:otp] = ask("OTP: ") { |q| q.echo = '*' }

    # config file
    options[:config] = ask("Config file path: ") { |q| q.default = "#{env}" }

    # loglevel
    options[:loglevel] = ask("Loglevel: ") { |q| q.default = 'INFO' }

    # timeout
    options[:timeout] = ask("Timeout: ") { |q| q.default = '60' }

    options[:verbose] = verbose

    options[:interactive] = true

    if args.include? '-d'
      options[:disconnect] = true
    end

    options

  end  # opt_prompt()

  ##
  ### Disconnect session:
  ##
  
  def self.disconnect(verbose = false, env, args)

    puts "* "*10
    puts "* * Disconnecting OpenVPN client connection"
    puts "* "*10
    
    options = {}

    # set disconnection
    options[:disconnect] = true

    # find config file in ARGV
    options[:config] = env

    if verbose
      options[:verbose] = true
      options[:loglevel] = 'INFO'
    else
      options[:loglevel] = 'ERROR'
    end

    if args.include? '-i'
      options[:interactive] = true
    else
      options[:interactive] = false
    end

    options

  end  # opt_prompt()

  ##
  ### Describe usage:
  ##

  def self.usage

    puts "* "*10
    puts "\tOpenVPN client via yubikey for 2FA"
    puts "\n usage : " 
    puts "\t #{$0} [ENV] (options)" 
    puts "* "*3
    puts "\t options : " 
    puts "\n\t -i | --interactive \t\t --- Run interactively"
    puts "\t -d | --disconnect \t\t --- Disconnect VPN ... \n\n or alternatively, supply (all mandatory): " 
    puts "\n\t -u | --username \t\t--- PAM|Unix username"
    puts "\t -p | --password \t\t--- PAM|Unix password"
    puts "\t -o | --otp \t\t\t--- Yubikey one-time-password"
    puts "\t -c | --config \t\t\t--- OpenVPN config file - contains connection details"
    puts "\n Optional:"
    puts "\n\t -v | --verbose \t\t --- enable verbose output for debugging"
    puts "\t -t | --timeout \t\t --- Set timeout value in seconds - defaults to 60 seconds"
    puts "\n" 
    puts "* "*10

  end

end  # class OptpromptOpenVPN

##
### MAIN CLASS:
##

class OpenVPNwithOTP

  def initialize(options)

    ## set instance vars
    @timestamp = Time.now.strftime("%Y-%m-%d-%H%M-%S")
  
    @username = options[:username]
    @password = options[:password]
    @otp = options[:otp]
    @config = options[:config]
    @timeout = options[:timeout].to_i
    @interactive = options[:interactive]

    @script_id = File.basename(@config.to_s)
    @script_instance = @script_id + "-" + Etc.getlogin

    @workingdir = "/var/tmp/#{@script_instance}"

    FileUtils.mkdir_p(@workingdir) unless File.directory?(@workingdir)
    File.chmod(0700, @workingdir)

    @sudoperm = "#{@workingdir}/ovpn-sudoperm"
    @killwrapper = "#{@workingdir}/ovpn-killpid"

    @ovpn_bin = `which openvpn`.chomp

    @passfile = "#{@workingdir}/#{@script_instance}.pass"
    @pidfile = "#{@workingdir}/#{@script_instance}.pid"
    @logfile = "#{@workingdir}/#{@script_instance}.log"

    @logsuccess = 'Initialization Sequence Completed'
    @logfailed = '(ECONNREFUSED|EHOSTUNREACH)'
    @authfailed = '(AUTH_FAILED)'
    @inactivitytimeout = '(Inactivity timeout)'

    @myuser = Etc.getlogin

    if options[:verbose]
      logger(options[:loglevel])
      @log_enabled = true
    else
      @log_enabled = false
    end

    File.open(@sudoperm.to_s, 'w') { |f|
      f.puts "#!/bin/bash"
      f.puts "sudo chown -R #{@myuser} #{@workingdir}"
    }

    File.chmod(0700, @sudoperm)

  end

  #
  ### Check prerequisites
  #

  def check_prereqs(options)

    failed_check = false

    options.each_pair { |k,v| 
      if v.nil?
        @log.fatal("#{k} is a mandatory option") if @log_enabled
        puts " #{k} is a mandatory option"
        failed_check = true
      end
    }

    if ! options[:disconnect]

      if @ovpn_bin.empty? or @ovpn_bin.nil?
        @log.fatal("OpenVPN not installed") if @log_enabled
        puts "OpenVPN not currently installed, or not in $PATH ... exiting"
        failed_check = true
      end

      if ! File.file?(@config.to_s)
        @log.fatal("Config file does not exist") if @log_enabled
        puts "OpenVPN config file does not exist ... exiting"
        failed_check = true
      end

    end

    if failed_check
      puts "One or more pre-requisites failed"
      exit 1
    end

  end

  ##
  ### Define Logger:
  ##

  def logger(level)

    @loglevel = level

    @log ||= Logger.new(STDOUT)

    @log.datetime_format = "%Y-%m-%d %H:%M:%S"

    case @loglevel.to_s
    when '10','DEBUG'
      @log.level = Logger::DEBUG
    when '20','INFO'
      @log.level = Logger::INFO
    when '30','WARN'
      @log.level = Logger::WARN
    when '40','ERROR'
      @log.level = Logger::ERROR
    else
      @log.fatal("Log level not within range: use range 10 to 40 or DEBUG to ERROR")
      abort("unrecognised log level defined... exiting")
    end

    @log.info ('*'*10)
    @log.info ("** OpenVPN via YubiKey OTP starting \t AT: #{@timestamp} **** ")
    @log.info ('*'*10)

  end

  ##
  ### Connect to VPN:
  ##

  def connect_vpn

    passfile = @passfile

    if RUBY_PLATFORM =~ /darwin/
      passfile = ''
    else
      File.open(passfile, 'w') { |f|
        f.puts @username
        f.puts @password + @otp
      }
      File.chmod(0600, @passfile)
    end

    puts "* "*10
    puts "* * \t Starting Connection to OpenVPN, using Yubikey 2FA \t * *"
    puts "* "*10

    vpn_log = []

    ## find other possible instances of wrapper script running
  
    ovpn_pid = get_process_id
  
    if ! ovpn_pid.nil?
      @log.info("Process list shows that an openVPN session, appears to already be running... with PID: #{ovpn_pid}") if @log_enabled
      manage_connection
      exit 0
    end

    if File.exists?(@pidfile)
      ovpn_pid = File.read(@pidfile).to_i
      @log.info("an existing pidfile shows an OpenVPN process created by you ... with PID: #{ovpn_pid}") if @log_enabled
      manage_connection
    end

    begin

      ## initiate our connection, then grab the exit status and read the pid it creates
      
      system("sudo #{@ovpn_bin} --config #{@config} --auth-user-pass #{passfile} --writepid #{@pidfile} --daemon --log #{@logfile}")
      exit_s = $?.exitstatus
      if File.exists?(passfile)
        File.delete(passfile)
      end
      if exit_s != 0
        @log.fatal("OpenVPN connection failed") if @log_enabled
        exit 1
      end

      ovpn_pid = get_process_id

      system("sudo #{@sudoperm}")

      begin

        Timeout.timeout(@timeout) do    # set timeout for connect
          File.open(@logfile, 'r') do |f|  # open logfile

            f.extend(File::Tail)
            f.interval = @timeout
            f.backward(10)
            f.tail { |line|

              @log.info(line.chomp) if @log_enabled
              vpn_log << line.chomp

              if line =~ /#{@authfailed}/
                @log.fatal("Authentication failed!") if @log_enabled
                puts "* * * \n Authentication with OpenVPN failed! \n * * *"
                kill_and_clean(ovpn_pid)
                exit 1
              end

              if line =~ /#{@logfailed}/
                @log.fatal("Connection failed!") if @log_enabled
                puts "* * * \n connection to OpenVPN failed! \n * * *"
                if @interactive and ! agree("Retry conection? ", true)
                  kill_and_clean(ovpn_pid)
                  exit 1
                end
              end

              if line =~ /#{@logsuccess}/
                @log.info("OpenVPN Connection established") if @log_enabled
                puts "* * * \n OpenVPN Connection established \n * * *"
                return
              end

            } # end tail

          end # end logfile

        end # end timeout

      rescue Timeout::Error => e
        @log.error("#{e} Timeout reached") if @log_enabled
        puts "Connection not established within #{@timeout} seconds"
        kill_and_clean(ovpn_pid)
        exit 1
      end

    end while @interactive and agree(".. Connection not established, retry conection? ", true)

  end

  ##
  ### Manage connection:
  ##

  def manage_connection

    vpn_log = []

    if File.exists?(@logfile)
      File.open(@logfile, 'r') { |f| f.each_line { |line| vpn_log << line.chomp } }
    end

    if File.exists?(@pidfile)
      ovpn_pid_from_file = File.read(@pidfile).to_i
      ovpn_pid = get_process_id
      if ovpn_pid != ovpn_pid_from_file
          puts "Pid file contains PID different to currently running process #{ovpn_pid}"
      end
    else
      ovpn_pid = get_process_id
    end

    if ! ovpn_pid.nil?

      begin

        Process.getpgid(ovpn_pid)
        log_pos = vpn_log.count
        if log_pos > 10
          max_pos = 10
        else
          max_pos = log_pos.to_i
        end
        vpn_log[-max_pos..-1].each { |t|

          if t =~ /#{@logsuccess}/
            puts "OpenVPN connection already established .."
            if @interactive
              if agree("Stay connected? ", true)
                puts "Maintaining connection, as requested"
                return
              else
                puts "Killing OpenVPN process with PID: #{ovpn_pid}"
                kill_and_clean(ovpn_pid)
                exit 0
              end
            end
            exit 0
          end

          if t =~ /#{@inactivitytimeout}/
            puts "OpenVPN connection timed-out previously .."
            if @interactive
              if agree("Reconnect VPN? ", true)
                puts "Maintaining connection, as requested"
              else
                puts "Cleaning up OpenVPN process with PID: #{ovpn_pid}"
                kill_and_clean(ovpn_pid)
                exit 0
              end
            end
          end

        } ## end tail of logarray

      rescue Errno::ESRCH => e
        puts "Pid file exists, but process not running ... deleting PID file for pid #{e}"
        if File.exists?(@pidfile)
          File.delete(@pidfile)
        end
      end
    
    else

      log_pos = vpn_log.count
      if log_pos > 10
        max_pos = 10
      else
        max_pos = log_pos.to_i
      end
      vpn_log[-max_pos..-1].each { |t|

        if t =~ /#{@inactivitytimeout}/
          puts "OpenVPN connection timed-out previously .."

          if @interactive
            if agree("Reconnect VPN? ", true)
              puts "Reconnecting, as requested"
            else
              puts "Not reconnecting .. "
              exit 0
            end
          end
        end
      }

    end

  end # end manage connection

  ##
  ### Disconnect VPN
  ##

  def disconnect(verbose = false)

    if File.exists?(@pidfile)

      ovpn_pid_from_file = File.read(@pidfile).to_i
      ovpn_pid = get_process_id
      if ovpn_pid != ovpn_pid_from_file
        puts "Pid file contains PID different to currently running process #{ovpn_pid}"
        ovpn_pid = ovpn_pid_from_file
      end

    else
      ovpn_pid = get_process_id
    end

    if ! ovpn_pid.nil?
      begin
        Process.getpgid(ovpn_pid)
        if @interactive
          if agree("Disconnect VPN? ", true)
            kill_and_clean(ovpn_pid)
            exit 0
          end
        else
          kill_and_clean(ovpn_pid)
          exit 0
        end
      rescue Errno::ESRCH => e
        puts "#{ovpn_pid} PROCESS does not exist ... #{e}"
        if File.exists?(@pidfile)
          File.delete(@pidfile)
        end
        exit 1
      end
    else
      puts "No OpenVPN process appears to be running"
      exit 0
    end

  end

  ##
  ### Kill and Clean
  ##

  def kill_and_clean(ovpn_pid)

    File.open(@killwrapper, 'w') { |f|
      f.puts "#!/bin/bash"
      f.puts "sudo kill #{ovpn_pid}"
    }
    File.chmod(0700, @killwrapper)

    begin
      if Process.getpgid(ovpn_pid)
        system("sudo #{@killwrapper}")
        exit_s = $?.exitstatus
        if exit_s != 0
          @log.fatal("Failed to disconnect VPN") if @log_enabled
          exit 1
        else 
          @log.info("OpenVPN process with PID: #{ovpn_pid} disconnected") if @log_enabled
        end
      end
    rescue Errno::ESRCH 
      puts "No Process to kill"
    end

    File.delete(@pidfile) if File.exists?(@pidfile)
    File.delete(@passfile) if File.exists?(@passfile)
    File.delete(@killwrapper) if File.exists?(@killwrapper)
    File.delete(@sudoperm) if File.exists?(@sudoperm)

  end

  ##
  ### Get Process ID:
  ##

  def get_process_id

    pid_array = []
    ProcTable.ps{ |p|
      pid_array << p.pid if p.comm == "openvpn" and p.cmdline =~ /#{@config}/
    }
    if pid_array.empty?
      @log.info("no OpenVPN process appears to be running") if @log_enabled
    else
      if pid_array.count.to_s == "1"
        ovpn_pid = pid_array[0]
      else
        puts "There appears to be more than one OpenVPN process running, for config file #{@config}!"
        puts "Check process lists and remove extra processes manually"
        exit 1
      end
    end

    ovpn_pid

  end

end ## - END MAIN CLASS

### Catch break

trap("INT") { 

  pp "CTRL-C detected... exiting" 
  if defined? openvpn_instance
    ovpn_pid = openvpn_instance.get_process_id
    openvpn_instance.kill_and_clean(ovpn_pid)
    exit
  else
    exit
  end

}

##
### Parse commandline args:
##

env = ARGV.shift

if ! env.nil? and env.length < 3 
  OptpromptOpenVPN.usage
  exit 1
end 

if env =~ /(admin|prod|pre|test)/
  env = Dir.pwd + "/config/" + Etc.getlogin + "-#{env}" + ".ovpn"
else
  puts "* "*10
  puts "ENV needs to be admin|prod|pre|test"
  puts "* "*10
  exit 1
end

if ARGV.count <= 4

  if ARGV.include? '-v'
    verbose = true
  else
    verbose = false
  end

  if ! ARGV.include? '-d'
    options = OptpromptOpenVPN.opt_prompt(verbose, env, ARGV)
  elsif ARGV.include? '-d'
    options = OptpromptOpenVPN.disconnect(verbose, env, ARGV)
  else
    options = OptpromptOpenVPN.usage
    exit 0
  end

else
  options = OptparseOpenVPN.parse(env, ARGV)
end


##
## main class instantiation:
##

openvpn_instance = OpenVPNwithOTP.new(options)

openvpn_instance.check_prereqs(options)

if options[:disconnect]
  openvpn_instance.disconnect(options[:verbose])
else
  openvpn_instance.connect_vpn
end

#### END
