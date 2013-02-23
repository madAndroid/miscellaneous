#!/usr/bin/ruby

require 'optparse'
require 'optparse/time'
require 'ostruct'
require 'pp'
require 'set'
require 'fileutils'

class OptparseBackup

  def self.parse(args)
    
    options = {}
   
    opts = OptionParser.new do |opts|
      options[:banner] = "Usage: backup.rb [options]"

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
      options[:exc] = nil
      opts.on('-e', '--exclude glob', 'Any patterns to exclude') do |e|
        options[:exc] = e
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


class Backup

  def initialize(source, destination, exclude)
    @source = source
    @destination = destination
    @exclude = exclude
  end

  ## SRCs
  def get_src_fileset
    full_paths = @source + "/**/*"
    src_files = Set.new(Dir.glob(full_paths))
    src_files = src_files.delete_if { |file| File.directory?(file) }
    src_files = src_files.delete_if { |file| File.symlink?(file) }
  end

  ## DSTs
  def cp_src_to_dst(src_file_set)

    dst_base_dir = @destination.to_s + "/" + Time.now.strftime("%Y-%m-%d-%H%M")
  
    if defined? @exclude
      exc_string = @exclude.to_s
      final_set = src_file_set.delete_if { |file| file =~ /#{exc_string}/ }
    else
      final_set = src_file_set
    end

    for src in final_set
      dst_dir = dst_base_dir + File.dirname(src) 
      FileUtils.mkdir_p(dst_dir)
      FileUtils.cp(src, dst_dir)
    end

  end

end

foo = Backup.new( options[:src], options[:dst], options[:exc] )

fset = foo.get_src_fileset

foo.cp_src_to_dst(fset)

puts foo.inspect
