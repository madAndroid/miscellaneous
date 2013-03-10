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

      # server
      options[:server] = nil
      opts.on('-s', '--server [server]', 'OpenVPN server to connect to') do |u|
        options[:server] = u
      end

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
    
    options = {}

    options[:username] = nil

    # ovpn_server
    options[:server] = ask("Server: ")
  
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
    puts "\n OpenVPN client via yubikey for 2FA"
    puts "\n options: " 
    puts "\t -i \ --interactive  -- Run interactively... \n\n or alternatively, supply (all mandatory): " 
    puts "\n\t -s \ --server \t\t\t--- OpenVPN server"
    puts "\t -u \ --username \t\t--- PAM/Unix username"
    puts "\t -p \ --password \t\t--- PAM/Unix password"
    puts "\t -o \ --otp \t\t\t--- Yubikey one-time-password"
    puts "\t -c \ --config \t\t\t--- OpenVPN config file"
    puts "\n Optional:"
    puts "\n\t -v \ --verbose    -- enable verbose output for debugging"
  end

end  # class OptpromptOpenVPN


class OpenVPNwithOTP

  def initialize(options)

    ## parse all args
  
    @server = options[:server]
    @username = options[:username]
    @password = options[:password]
    @otp = options[:otp]
    @config = options[:config]

    @timestamp = Time.now.strftime("%Y-%m-%d-%H%M-%S")

    options.each_pair { |k,v| 
      if v.nil?
        puts " #{k} is a mandatory option"
      end
    }

    if options[:verbose]
      logger(options[:loglevel])
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

