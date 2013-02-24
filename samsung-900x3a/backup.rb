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
      opts.on('-s', '--src [dir]', 'Source directory to backup') do |s|
        options[:src] = s
      end

      # destination
      options[:dst] = nil
      opts.on('-d', '--dst dir', 'Destination directory to backup to') do |d|
        options[:dst] = d
      end

      # exclusions 
      options[:exc] = nil
      opts.on('-e', '--exclude glob', 'Any patterns to exclude') do |e|
        options[:exc] = e
      end

      # days to keep
      options[:keep] = '3'
      opts.on('-k', '--keep days', 'Any patterns to exclude') do |k|
        options[:keep] = k
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

#  def initialize(source, destination, exclude)
  def initialize(options)

    @source = options[:src]
    @destination = options[:dst]
    @exclude = options[:exc]
    @keep = options[:keep]

    @timestamp = Time.now.strftime("%Y-%m-%d-%H%M")
    @dst_base_dir = @destination.to_s + "/" + @source
    @dst_instance = @dst_base_dir + "/" + @timestamp

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

    if defined? @exclude
      exc_string = @exclude.to_s
      final_set = src_file_set.delete_if { |file| file =~ /#{exc_string}/ }
    else
      final_set = src_file_set
    end

    for src in final_set
      dst_dir = @dst_instance + File.dirname(src) 
      FileUtils.mkdir_p(dst_dir)
      FileUtils.cp(src, dst_dir)
    end

  end

  def rotate_backups(days_to_keep = @keep.to_i)

    dst_symlink = @dst_base_dir + "/current"

    ## remove old 'current' symlink
    if File.symlink?(dst_symlink)  
      FileUtils.rm(dst_symlink)
    end

    FileUtils.ln_sf(@dst_instance, dst_symlink)

    dirs = []

    dirs = Dir.entries(@dst_base_dir)

    dir_array = dirs.delete_if { |file| file =~ /(current)|(\.)|(\.\.)/ }

    target_dir_to_delete = dir_array.sort[0...-days_to_keep]

    for dir in target_dir_to_delete 
      FileUtils.remove_dir(@dst_base_dir + "/" + dir)
    end

  end

end

foo = Backup.new(options)
#foo = Backup.new( options[:src], options[:dst], options[:exc] )

fset = foo.get_src_fileset

foo.cp_src_to_dst(fset)

foo.rotate_backups

