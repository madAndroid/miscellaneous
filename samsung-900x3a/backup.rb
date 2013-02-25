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
      opts.on('-s', '--src [dir(s)]', Array, 'Source directory(s) to backup') do |s|
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

  def initialize(options)

    @sources = options[:src]
    @destination = options[:dst]
    @exclude = options[:exc]
    @keep = options[:keep]

    @timestamp = Time.now.strftime("%Y-%m-%d-%H%M")

  end

  def set_dst_path(src_dir)

    pretty_src = src_dir.gsub( /\// , '-' ).gsub( /^-/, '')
    dst_base_dir = @destination.to_s + "/" + pretty_src
    dst_instance = dst_base_dir + "/" + @timestamp

  end


  ## SRCs
  def get_src_fileset

    dir_hash = Hash.new { |s,p| s[p] = [] }

    src_array = @sources
    
    src_array.each { |path|
      full_paths = path + "/**/*"
      src_files = Dir.glob(full_paths)
      src_files.delete_if { |file| (File.symlink?(file) || File.directory?(file)) } 
      src_files.each { |src| dir_hash[path] << src }
    }    
   
    rhash = dir_hash

  end


  ## DSTs
  def cp_src_to_dst(src_dir, src_file_set)

    dst_instance = set_dst_path(src_dir)

    if defined? @exclude
      exc_string = @exclude.to_s
      final_array = src_file_set.delete_if { |file| file =~ /#{exc_string}/ }
    else
      final_array = src_file_set
    end

    final_array.each { |src|
      dst_dir = dst_instance + File.dirname(src) 
      FileUtils.mkdir_p(dst_dir)
      FileUtils.cp(src, dst_dir)
    }

  end

  def rotate_backups(src_dir, days_to_keep = @keep.to_i)

    dst_instance = set_dst_path(src_dir)

    dst_base_dir = @destination.to_s + "/" + src_dir

    dst_symlink = dst_base_dir + "/current"

    ## remove old 'current' symlink
    if File.symlink?(dst_symlink)  
      FileUtils.rm(dst_symlink)
    end

    FileUtils.ln_sf(dst_instance, dst_symlink)

    dirs = []

    dirs = Dir.entries(dst_base_dir)

    dir_array = dirs.delete_if { |file| file =~ /(current)|(\.)|(\.\.)/ }

    puts dir_array

    target_dir_to_delete = dir_array.sort[0...-days_to_keep]

    puts target_dir_to_delete

    for dir in target_dir_to_delete 
      FileUtils.remove_dir(dst_base_dir + "/" + dir)
    end

  end

end

back_it_up = Backup.new(options)

fset_hash = {}
fset_hash = back_it_up.get_src_fileset

pp fset_hash

fset_hash.each { |src_dir, src_file_set|
  back_it_up.cp_src_to_dst(src_dir, src_file_set)
  back_it_up.rotate_backups(src_dir)
}

