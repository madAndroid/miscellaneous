#!/usr/bin/ruby

require 'optparse'
require 'optparse/time'
require 'ostruct'
require 'pp'

class OptparseBackup

  #
  # Return a structure describing the options.
  #
  def self.parse(args)
    # The options specified on the command line will be collected in *options*.
    # We set default values here.
    options = OpenStruct.new
    options.library = []
    options.inplace = false
    options.encoding = "utf8"
    options.transfer_type = :auto
    options.verbose = false

    opts = OptionParser.new do |opts|
      opts.banner = "Usage: backup.rb [options]"

      opts.separator ""
      opts.separator "Specific options:"

      # source
      options[:src] = nil
      opts.on('-s', '--src directory', 'Source directory to backup') do |s|
        options[:src] = s
      end

      # source
      options[:dst] = nil
      opts.on('-d', '--dst directory', 'Destination directory to backup to') do |d|
        options[:dst] = d
      end

      # source
      options[:exclude] = nil
      opts.on('-e', '--exclude glob', 'Any patterns to exclude') do |e|
        options[:exclude] = e
      end

      # Boolean switch.
      options[:verbose] = nil
      opts.on("-v", "--[no-]verbose", "Run verbosely") do |v|
        options[:verbose] = v
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

end  # class OptparseBackup

options = OptparseBackup.parse(ARGV)
pp options

class Backup

  def initialize(source, destination, excludes)
    @source = source
    @destination = destination
    @excludes = excludes
  end
  
end


