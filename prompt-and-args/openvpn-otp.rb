#!/usr/bin/ruby

require 'optparse'
require 'optparse/time'
require 'ostruct'
require 'pp'
require 'set'
require 'fileutils'
require 'logger'
require 'highline/import'


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
      opts.on("-i", "--[non-]interactive", "Run Interactively") do |i|
        options[:interactive] = i
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

    options[:verbose] = verbose

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

    @ovpn_binary = `which openvpn`

    @timestamp = Time.now.strftime("%Y-%m-%d-%H%M-%S")

    options.each_pair { |k,v| 
      if v.nil?
        puts " #{k} is a mandatory option"
      end
    }

    if options[:verbose]
      logger(options[:loglevel])
      @log_enabled = true
    end
      
  end

  def check_prereqs

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
    passfile = '/tmp/passfile'
    pidfile = '/tmp/pidfile'
    logfile = '/tmp/openvpn.log'

    File.open(passfile, 'w') { |f|
      f.puts @username
      f.puts @password + @otp
    }

    ovpn_output = []

    ovpn_output = `#{ovpn_bin} --config #{confile} --auth-user-pass #{passfile} --writepid #{pidfile} --daemon --log #{logfile}`

    pid = $?.pid
    exit_s = $?.exitstatus

    if exit_s != 0
      @log.fatal("OpenVPN connection failed") if @log_enabled
    end

    vpn_log = []

    File.open(logfile, 'r') { |f|
      f.each_line do |line|
        @log.fatal(line.chomp) if @log_enabled
        vpn_log << line.chomp
      end
    }

  end

end

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

openvpn_run = OpenVPNwithOTP.new(options)

openvpn_run.check_prereqs

openvpn_run.connect_vpn
