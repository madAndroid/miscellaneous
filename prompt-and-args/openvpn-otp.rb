#!/usr/bin/ruby

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
rescue LoadError => e
  raise unless e.message =~ /(highline|file-tail)/
  puts "file-tail and highline are gem dependencies and must be installed" 
end

class OptparseOpenVPN

  def self.parse(args)
    
    options = {}
   
    opts = OptionParser.new do |opts|
      options[:banner] = "Usage: backup.rb [options]"

      # username
      options[:username] = nil
      opts.on('-u', '--username [USERNAME]', 'Unix/PAM username') do |u|
        options[:username] = u
      end

      # password
      options[:password] = nil
      opts.on('-p', '--password [PASSWORD]', 'Password for USERNAME') do |p|
        options[:password] = p
      end

      # OTP
      options[:otp] = nil
      opts.on('-o', '--otp [ONETIMEPASSWORD]', 'Onetime password') do |o|
        options[:otp] = o
      end

      # OTP
      options[:config] = nil
      opts.on('-c', '--config [config_file]', 'OpenVPN config file') do |c|
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

      # interactive
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


class OptpromptOpenVPN

  def self.opt_prompt(verbose = false)

    puts "* "*10
    puts "OpenVPN client connection using YubiKey OTP"
    puts "* "*10
    
    options = {}

    # username
    options[:username] = ask("Username: ")

    # password
    options[:password] = ask("Password: ") { |q| q.echo = '*' }

    # OTP
    options[:otp] = ask("OTP: ") { |q| q.echo = '*' }

    # loglevel
    options[:config] = ask("Config file path: ")

    # loglevel
    options[:loglevel] = ask("Loglevel: ") { |q| q.default = 'INFO' }

    # timeout
    options[:timeout] = ask("Timeout: ") { |q| q.default = '60' }

    options[:verbose] = verbose

    options[:interactive] = true

    options

  end  # opt_prompt()

  def self.usage
    puts "* "*10
    puts "\tOpenVPN client via yubikey for 2FA"
    puts "\n options: " 
    puts "\t -i \ --interactive  -- Run interactively... \n\n or alternatively, supply (all mandatory): " 
    puts "\n\t -u \ --username \t\t--- PAM/Unix username"
    puts "\t -p \ --password \t\t--- PAM/Unix password"
    puts "\t -o \ --otp \t\t\t--- Yubikey one-time-password"
    puts "\t -c \ --config \t\t\t--- OpenVPN config file - contains connection details"
    puts "\n Optional:"
    puts "\n\t -v \ --verbose    -- enable verbose output for debugging"
    puts "\n" 
    puts "* "*10

  end

end  # class OptpromptOpenVPN


class OpenVPNwithOTP

  def initialize(options)

    ## parse all args
  
    @username = options[:username]
    @password = options[:password]
    @otp = options[:otp]
    @config = options[:config]
    @timeout = options[:timeout]
    @interactive = options[:interactive]

    @ovpn_binary = `which openvpn`
    @passfile = '/tmp/passfile'
    @pidfile = '/tmp/pidfile'
    @logfile = '/tmp/openvpn.log'

    @timestamp = Time.now.strftime("%Y-%m-%d-%H%M-%S")

    if options[:verbose]
      logger(options[:loglevel])
      @log_enabled = true
    end
      
  end

  def check_prereqs(options)

    options.each_pair { |k,v| 
      if v.nil?
        @log.fatal("#{k} is a mandatory option") if @log_enabled
        puts " #{k} is a mandatory option"
      end
    }

    if @ovpn_binary.empty? or @ovpn_binary.nil?
      @log.fatal("OpenVPN not installed") if @log_enabled
      abort("OpenVPN not currently installed ... exiting")
    end

    if ! File.file?(@config.to_s)
      @log.fatal("Config file does not exist") if @log_enabled
      abort("OpenVPN config file does not exist ... exiting")
    end

  end

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

  def connect_vpn

    ovpn_bin = @ovpn_binary.chomp
    confile = @config
    passfile = @passfile
    pidfile = @pidfile
    logfile = @logfile
    timeout = @timeout.to_i

    logsuccess = 'Initialization Sequence Completed'
    logfailed = '(ECONNREFUSED|connection failed)'

    File.open(passfile, 'w') { |f|
      f.puts @username
      f.puts @password + @otp
    }

    puts "* "*10
    puts "* * \t Starting Connection to OpenVPN, using Yubikey 2FA \t * *"
    puts "* "*10

    vpn_log = []
    ovpn_output = []

    if File.exists?(pidfile)

      ovpn_pid = File.read(pidfile).to_i
      @log.info("an OpenVPN process appears to already be running... with PID: #{ovpn_pid}") if @log_enabled
      
      manage_connection

    else

      ovpn_output = `#{ovpn_bin} --config #{confile} --auth-user-pass #{passfile} --writepid #{pidfile} --daemon --log #{logfile}`

      pid = $?.pid
      exit_s = $?.exitstatus

      if exit_s != 0
        @log.fatal("OpenVPN connection failed") if @log_enabled
      end

      status = Timeout::timeout(timeout) {    # set timeout for connect

        File.open(logfile, 'r') do |f|  # open logfile

          f.extend(File::Tail)
          f.interval = 10
          f.backward(10)
          f.tail { |line|

            @log.info(line.chomp) if @log_enabled
            vpn_log << line.chomp

            if line =~ /#{logfailed}/
              @log.fatal("Connection failed!") if @log_enabled
              abort("* * * \n connection to OpenVPN failed! \n * * *")
            end

            if line =~ /#{logsuccess}/
              @log.info("OpenVPN Connection established") if @log_enabled
              puts "* * * \n OpenVPN Connection established \n * * *"
              return
            end

          } # end tail

        end # end logfile

      } # end timeout

    end # end if

  end


  def manage_connection

    logfile = @logfile
    pidfile = @pidfile
    interact = @interactive
    vpn_log = []
    logsuccess = 'Initialization Sequence Completed'

    File.open(logfile, 'r') do |f|
      f.each_line { |line|
        vpn_log << line.chomp
      }
      f.close
    end

    ovpn_pid = File.read(pidfile).to_i

    begin

      Process.getpgid(ovpn_pid)

      if vpn_log[-1] =~ /#{logsuccess}/

        puts "OpenVPN connection already established .."

        if interact

          if agree("Stay connected? ", true)
            puts "Maintaining connection, as requested"
            return
          else
            puts "Killing OpenVPN process with PID: #{ovpn_pid}"
            begin
              Process.kill('HUP', ovpn_pid)
              File.delete(pidfile)
            rescue
              puts "could not kill process"
            end
          end

        end

      end

    rescue Errno::ESRCH => e

      puts "Pid file exists, but process not running"

      puts interact.inspect

      if interact
        if agree("Delete PID file? ", true)
          File.delete(pidfile)
        end
      end

    end

  end

end


### Parse commandline args:

if ARGV.count <= 2

  if ARGV.include? '-i' and ARGV.include? '-v'
    options = OptpromptOpenVPN.opt_prompt(true)
  elsif 
    ARGV.include? '-i' and ARGV.count <= 1
    options = OptpromptOpenVPN.opt_prompt
  else
    options = OptpromptOpenVPN.usage
    exit 1
  end

else
  options = OptparseOpenVPN.parse(ARGV)
end

## main class instantiation:
#
openvpn_run = OpenVPNwithOTP.new(options)

openvpn_run.check_prereqs(options)

openvpn_run.connect_vpn

#openvpn_run.prompt_disconnect

