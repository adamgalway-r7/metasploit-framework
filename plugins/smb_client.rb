# -*- coding:binary -*-

require 'fileutils'
require 'ruby_smb'

module Msf

  class Plugin::SMBClient < Msf::Plugin

    class SMBClientCommandDispatcher
      include Msf::Ui::Console::CommandDispatcher

      def name
        'SMB_Client'
      end

      def commands
        {
          'smb_init'          => 'Initialize the SMB Client',
          'smb_read'          => 'Read a file',
          'smb_write'         => 'Write a file'
        }
      end

      def cmd_smb_init(*args)
        @protocol = nil
        @status = nil

        @smb_config = {
          address: nil,
          username: nil,
          password: nil,
          share: nil
        } if @smb_config.nil? || @smb_config.empty?

        return unless parse_config(*args, @smb_config)

        sock = TCPSocket.new @smb_config[:address], 445
        dispatcher = RubySMB::Dispatcher::Socket.new(sock)

        @path = "\\\\#{@smb_config[:address]}\\#{@smb_config[:share]}"

        begin
          @client = RubySMB::Client.new(dispatcher, smb1: true, smb2: true,
                                        username: @smb_config[:username], password: @smb_config[:password],
                                        always_encrypt: false)
          @protocol = @client.negotiate
          @status = @client.authenticate
        rescue => e
          print_error("Negotiation or Authentication failed with #{e} exception:\n #{e.backtrace}")
        end

        if !@status.nil? && @status.name == 'STATUS_SUCCESS'
          print_good('Initialization succeeded.')
        else
          print_bad('Initialization failed.')
          @client = nil
        end
      end

      def cmd_smb_write(*args)
        if @client.nil?
          print_error('SMB Connection must be initialized with smb_init.')
        end

        write_config = {
          remote_file_path: nil,
          local_file_path: nil
        }

        return unless parse_config(*args, write_config)

        local_file_path = expand_file_path(write_config[:local_file_path])
        return if local_file_path.nil?
        remote_file_path = write_config[:remote_file_path]

        unless local_file_path.exist?
          print_error('Local File does not exist.')
          return
        end

        if local_file_path.directory?
          print_error('Local File is a directory.')
          return
        end

        unless local_file_path.readable?
          print_error('Local File is not readable.')
          return
        end

        begin
          tree = @client.tree_connect(@path)
          print_good("Connected to #{@path} successfully.")
        rescue StandardError => e
          reset_broken_smb_connection("Failed to connect to #{@path}: #{e.message}")
          return
        end

        remote_file = tree.open_file(filename: remote_file_path, write: true,
                                     disposition: RubySMB::Dispositions::FILE_OVERWRITE_IF)

        server_response = remote_file.write(data: local_file_path.read)

        if server_response.name == 'STATUS_SUCCESS'
          print_good("Local file #{local_file_path} has been successfully written to remote file #{remote_file_path}")
        else
          print_bad("Unexpected error when writing file\n#{server_response.name}: #{server_response.description}")
        end

        remote_file.close
      end

      def cmd_smb_read(*args)
        if @client.nil?
          print_error('SMB Connection must be initialized with smb_init.')
        end

        read_config = {
          remote_file_path: nil,
          local_file_path: nil
        }

        return unless parse_config(*args, read_config)

        local_file_path = expand_file_path(read_config[:local_file_path])
        return if local_file_path.nil?
        remote_file_path = read_config[:remote_file_path]

        begin
          tree = @client.tree_connect(@path)
          print_good("Connected to #{@path} successfully!")
        rescue StandardError => e
          reset_broken_smb_connection("Failed to connect to #{@path}: #{e.message}")
        end

        begin
          remote_file = tree.open_file(filename: remote_file_path)

          data = remote_file.read
          local_file_path.write(data)
        rescue => e
          print_bad("Unexpected error when writing file\n#{e.name}: #{e.backtrace}")
          return
        end

        print_good("Remote file #{remote_file_path} has been successfully written to local file #{local_file_path}")
        remote_file.close
      end

      private

      def parse_config(*args, config)
        new_config = args.map{|x| x.split("=", 2) }
        valid_args = true

        config.keys.each do |key|
          unless new_config.any? { |a| a.include?(key.to_s) }
            print_error("'#{key}' must be included as an argument")
            valid_args = false
          end
        end

        return false unless valid_args

        new_config.each do |c|
          unless config.has_key?(c.first.to_sym)
            print_error("Invalid configuration option: #{c.first}")
            valid_args = false
            next
          end

          if c.length == 1
            print_error("No value has been assigned to the configuration option #{c.first}")
            valid_args = false
            next
          end

          config[c.first.to_sym] = c.last
        end

        valid_args
      end

      def fix_broken_pipe
        sock = TCPSocket.new @smb_config[:address], 445
        dispatcher = RubySMB::Dispatcher::Socket.new(sock)

        begin
          @client = RubySMB::Client.new(dispatcher, smb1: true, smb2: true, username: @smb_config[:username], password: @smb_config[:password])
          @protocol = @client.negotiate
          @status = @client.authenticate
        rescue => e
          print_error("Negotiation or Authentication failed with #{e} exception:\n #{e.backtrace}")
        end
      end

      def reset_broken_smb_connection(err_msg)
        print_error(err_msg)
        fix_broken_pipe
      end

      def expand_file_path(path)
        if path[0].to_s == '~' || path[0..1] == './' || path[0..2] == '../'
          expanded_path = Pathname(File.expand_path(path))

          unless expanded_path.exist?
            print_bad("File at #{expanded_path} does not exist.")
            return nil
          end

          return expanded_path
        end

        # This will prepend the +path+ variable with the current directory metasploit is being run from
        # This behaviour is only carried out with +expand_path+ if the passed string doesn't start with "~", "./", or "../"
        absolute_path = Pathname(File.expand_path(path))
        unaltered_path = Pathname(path)

        if absolute_path.exist?
          absolute_path
        elsif unaltered_path.exist?
          unaltered_path
        else
          print_bad("File could not be found at either #{unaltered_path} or #{absolute_path}.")
          nil
        end
      end
    end

    #
    # Plugin Interface
    #

    def initialize(framework, opts)
      super
      add_console_dispatcher(SMBClientCommandDispatcher)
    end

    def cleanup
      remove_console_dispatcher('SMB_Client')
    end

    def name
      'SMB_Client'
    end

    def desc
      'A fully featured SMB client'
    end
  end
end

