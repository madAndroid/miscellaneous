#!/usr/bin/ruby

require 'optparse'
require 'optparse/time'
require 'ostruct'
require 'pp'
require 'set'
require 'fileutils'
require 'logger'

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

      # source
      options[:srcs_file] = nil
      opts.on('-f', '--srcs_file [file_name]', 'File with directories to backup - one per line') do |s|
        options[:srcs_file] = s
      end

      # destination
      options[:dst] = nil
      opts.on('-d', '--dst dir', 'Destination directory to backup to') do |d|
        options[:dst] = d
      end

      # exclusions 
      options[:exc] = nil
      opts.on('-e', '--exclude [list]', Array, 'Any patterns to exclude') do |e|
        options[:exc] = e
      end

      # loglevel
      options[:loglevel] = 'INFO'
      opts.on("-l", "--loglevel level", 'Change Logging level') do |l|
        options[:loglevel] = l
      end

      # days to keep
      options[:keep] = '3'
      opts.on('-k', '--keep days', 'Any patterns to exclude') do |k|
        options[:keep] = k
      end

      # verbosity boolean switch.
      options[:verbose] = nil
      opts.on("-v", "--[no-]verbose", "Run verbosely") do |v|
        options[:verbose] = v
      end

      # Boolean switch.
      options[:pkgs] = nil
      opts.on("-p", "--[no-]pkgs", "Backup list of packages") do |p|
        options[:pkgs] = p
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

class MultiIO
  def initialize(*targets)
     @targets = targets
  end

  def write(*args)
    @targets.each {|t| t.write(*args)}
  end

  def close
    @targets.each(&:close)
  end
end

class Backup

  def initialize(options)

    ## Parse all but source options first:
    
    @loglevel = options[:loglevel]
    @destination = options[:dst]
    @exclude = options[:exc]
    @keep = options[:keep]

    @timestamp = Time.now.strftime("%Y-%m-%d-%H%M-%S")

    log_dir = @destination + "/backup-log"
    FileUtils.mkdir_p(log_dir) unless File.exists?(log_dir)
    log_file = File.open("/" + log_dir + "/" + "backup.rb.log", File::WRONLY | File::APPEND | File::CREAT)

    if options[:verbose]
      @log ||= Logger.new MultiIO.new(STDOUT,log_file)
    else
      @log ||= Logger.new(log_file, 10, 102400)
    end

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

    @log.info (" ***** \t ***** \t **** ")
    @log.info (" ***** \t Ruby BACKUP script starting ***** \t AT: #{@timestamp} **** ")
    @log.debug { " ***** \t With VARS: #{options}" }
    @log.debug { " ***** \t With SOURCE(s): #{@sources}" }
    @log.debug { " ***** \t With DESTINATION: #{@destination}" }
    @log.debug { " ***** \t With EXCLUSIONS: #{@exclude}" }

    ## Parse src options:

    if options[:src] and options[:srcs_file]
      @log.fatal("either src list or srcs_file needs to be defined - cannot use both")
      abort("Cannot specify both src list and srcs_file.. exiting")
    end

    if options[:srcs_file]
      if File.exists?(options[:srcs_file])
        sources = []
        File.open(options[:srcs_file], 'r') { |f|
          f.each_line do |line|
            sources << line.chomp
          end
        }
      else
        @log.fatal("Specified srcs_list file does not exist.. exiting")
        abort("Specified srcs_list file does not exist.. exiting")
      end
      @sources = sources
    else
      @sources = options[:src]
    end
      
  end

  def set_dst_path(src_dir)

    @log.info "---- starting backup for #{src_dir} ------"

    pretty_src = src_dir.gsub( /\// , '-' ).gsub( /^-/, '')
    dst_base_dir = @destination.to_s + "/" + pretty_src
    dst_instance = dst_base_dir + "/" + @timestamp

  end

  ## SRCs
  def get_src_fileset

    ## initialize our hash of dirs
    dir_hash = Hash.new { |s,p| s[p] = [] }

    src_array = @sources

    ## Build our hash of dirs
    src_array.each { |path|
      full_paths = path + "/**/*"
      src_files = Dir.glob(full_paths)
      src_files.delete_if { |file| (File.symlink?(file) || File.directory?(file)) } 
      src_files.each { |src| dir_hash[path] << src }
    }    
   
    @log.debug "---- hash of dirs and paths: ------"
    @log.debug "---- #{dir_hash} ------"

    ## return the hash
    rhash = dir_hash

  end


  ## DSTs
  def cp_src_to_dst(src_dir, src_file_set)

    dst_instance = set_dst_path(src_dir)

    @log.info "Backing up #{src_dir} to #{dst_instance} at #{Time.now.strftime("%H:%M:%S")}"

    ## remove any exclusions from src
    if defined? @exclude
      @log.debug "Excluding #{@exclude} from #{src_dir}"
      exc_array = @exclude
      final_array = []
      exc_array.each { |exc| final_array = src_file_set.delete_if { |file| file =~ /#{exc}/ } }
    else
      final_array = src_file_set
    end

    final_array.each { |src|

      dst_dir = dst_instance + File.dirname(src) 

      @log.debug "---- Copying #{src} to #{dst_dir} ------"

      FileUtils.mkdir_p(dst_dir)
      FileUtils.cp(src, dst_dir)
    }

  end

  def rotate_backups(src_dir, days_to_keep = @keep.to_i)

    dst_instance = set_dst_path(src_dir)

    dst_base_dir = @destination.to_s + "/" + src_dir.gsub( /\// , '-' ).gsub( /^-/, '')

    dst_symlink = dst_base_dir + "/current"

    ## remove old 'current' symlink
    if File.symlink?(dst_symlink)  
      FileUtils.rm(dst_symlink)
    end

    @log.debug "---- symlinking #{dst_instance} to #{dst_symlink} ------"

    ## link our new current direcory
    FileUtils.ln_sf(dst_instance, dst_symlink)

    ## Find directories to delete as part of rotation
    dirs = []
    dirs = Dir.entries(dst_base_dir)
    dir_array = dirs.delete_if { |file| file =~ /(current)|(\.)|(\.\.)/ }

    target_dir_to_delete = dir_array.sort[0...-days_to_keep]

    @log.debug "---- keeping #{days_to_keep} of backups ---"
    @log.debug "---- removing #{target_dir_to_delete} as part of cleanup to ------"

    for dir in target_dir_to_delete 
      FileUtils.remove_dir(dst_base_dir + "/" + dir)
    end

  end

  def extras(pkg_tech, lists_to_keep = @keep.to_i)

    pkg_list_dir = @destination + "/package-lists/#{pkg_tech}"
    FileUtils.mkdir_p(pkg_list_dir) unless File.exists?(pkg_list_dir)

    if pkg_tech =~ /gem/
      pkg_list_cmd = "gem list"
    else
      pkg_list_cmd = "dpkg -l"
    end

    pkg_list = []
    pkg_list = `#{pkg_list_cmd}`.split(/\n/)
    pkg_list_file = pkg_list_dir + "/" + "#{pkg_tech}_list-#{@timestamp}.txt"

    tmp_pkg_fn = "/tmp/" + "#{pkg_tech}_list-#{@timestamp}.txt"
    tmp_pkg_file = File.open(tmp_pkg_fn, File::WRONLY | File::APPEND | File::CREAT)
    tmp_pkg_file.puts("*"*20)
    tmp_pkg_file.puts("#{pkg_tech} list")
    tmp_pkg_file.puts("*"*20)
    pkg_list.each { |g| tmp_pkg_file.puts(g) }

    tmp_pkg_file.close

    pkg_symlink = pkg_list_dir + "/current"

    ## Find files to delete as part of rotation
    files = []
    files = Dir.entries(pkg_list_dir).delete_if { |f|  (f =~ /current/ || File.directory?(f)) }

    if files.empty?

      FileUtils.mv tmp_pkg_fn, pkg_list_file
      @log.debug "---- symlinking #{pkg_list_file} to #{pkg_symlink} ------"
      ## link our new current file
      FileUtils.ln_sf(pkg_list_file, pkg_symlink)
   
    else

      last_file = pkg_list_dir + "/" + files.sort[-1]

      if ! FileUtils.compare_file(last_file, tmp_pkg_fn)

        FileUtils.mv tmp_pkg_fn, pkg_list_file

        ## remove old 'current' symlink
        if File.symlink?(pkg_symlink)  
          FileUtils.rm(pkg_symlink)
        end

        @log.debug "---- symlinking #{pkg_list_file} to #{pkg_symlink} ------"
        ## link our new current file
        FileUtils.ln_sf(pkg_list_file, pkg_symlink)

      end

      if files.count >= 3
        delete_list = files.sort[0...-3]
        for file in delete_list
          target_file = pkg_list_dir + "/" + file
          FileUtils.rm(target_file) unless File.symlink?(target_file)
        end
      end

    end
    
  end

end

back_it_up = Backup.new(options)

fset_hash = {}
fset_hash = back_it_up.get_src_fileset

fset_hash.each { |src_dir, src_file_set|
  back_it_up.cp_src_to_dst(src_dir, src_file_set)
  back_it_up.rotate_backups(src_dir)
}

if options.has_key?(:pkgs)
  back_it_up.extras('dpkg')
  back_it_up.extras('gem')
end

