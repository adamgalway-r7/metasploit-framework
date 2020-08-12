# -*- coding: binary -*-

require 'rex/post/smb/extension'
require 'rex/post/smb/object_aliases'
require 'msf/core/modules/shared/smblogic'


module Rex
  module Post
    module SMB

      class Connection
        include Msf::Modules::Shared::SmbLogic

        def initialize(args)
          @protocol = nil
          @status = nil

          @smb_config = args

          sock = TCPSocket.new @smb_config[:address], 445
          dispatcher = RubySMB::Dispatcher::Socket.new(sock)

          @path = "\\\\#{@smb_config[:address]}\\#{@smb_config[:share]}"

          begin
            @client = RubySMB::Client.new(dispatcher, smb1: true, smb2: true,
                                          username: @smb_config[:username], password: @smb_config[:password],
                                          always_encrypt: false)
            @protocol = @client.negotiate
            @status = @client.authenticate
            @current_dir = '/'
          rescue => e
            print("Negotiation or Authentication failed with #{e} exception:\n #{e.backtrace}")
          end
        end

        def write(args)
          # write_config = {
          #   remote_file_path: nil,
          #   local_file_path: nil
          # }
          #
          # return unless parse_config(*args, write_config)
          #
          # local_file_path = expand_file_path(write_config[:local_file_path])
          # return if local_file_path.nil?
          # remote_file_path = write_config[:remote_file_path]
          #
          # unless local_file_path.exist?
          #   print('Local File does not exist.')
          #   return
          # end
          #
          # if local_file_path.directory?
          #   print('Local File is a directory.')
          #   return
          # end
          #
          # unless local_file_path.readable?
          #   print('Local File is not readable.')
          #   return
          # end
          #
          # begin
          #   tree = @client.tree_connect(@path)
          #   raise "Client could not to #{@path}" if tree.nil?
          # rescue StandardError => e
          #   reset_broken_smb_connection("Failed to connect to #{@path}: #{e.message}")
          #   return
          # end
          #
          # remote_file = tree.open_file(filename: remote_file_path, write: true,
          #                              disposition: RubySMB::Dispositions::FILE_OVERWRITE_IF)
          #
          # server_response = remote_file.write(data: local_file_path.read)
          #
          # if server_response.name == 'STATUS_SUCCESS'
          #   print("Local file #{local_file_path} has been successfully written to remote file #{remote_file_path}")
          # else
          #   print("Unexpected error when writing file\n#{server_response.name}: #{server_response.description}")
          # end
          #
          # remote_file.close
        end

        def read(args)
          # read_config = {
          #   remote_file_path: nil,
          #   local_file_path: nil
          # }
          #
          # return unless parse_config(*args, read_config)
          #
          # local_file_path = expand_file_path(read_config[:local_file_path])
          # return if local_file_path.nil?
          # remote_file_path = read_config[:remote_file_path]
          #
          # begin
          #   tree = @client.tree_connect(@path)
          #   raise "Client could not to #{@path}" if tree.nil?
          # rescue StandardError => e
          #   reset_broken_smb_connection("Failed to connect to #{@path}: #{e.message}")
          # end
          #
          # begin
          #   remote_file = tree.open_file(filename: remote_file_path)
          #
          #   data = remote_file.read
          #   local_file_path.write(data)
          # rescue => e
          #   print("Unexpected error when writing file\n#{e.name}: #{e.backtrace}")
          #   return
          # end
          #
          # print("Remote file #{remote_file_path} has been successfully written to local file #{local_file_path}")
          # remote_file.close
        end

        def ls
          tree = nil
          begin
            tree = @client.tree_connect(@path)
            raise "Client could not to #{@path}" if tree.nil?
          rescue StandardError => e
            reset_broken_smb_connection("Failed to connect to #{@path}: #{e.message}")
          end

          dirs = []
          files = []

          tree.list.each { |tree_object|
            if tree_object[:file_attributes][:directory] == 1
              dirs << tree_object
            else
              files << tree_object
            end
          }

          # Display the commands
          tbl = Rex::Text::Table.new(
            'Header' => "Contents of #{@smb_config[:share]} ",
            'Indent' => 4,
            'Columns' =>
              [
                'Type',
                'Name',
                'Create Time',
                'Last Edit',
                'Size in Bytes',
              ],
            'ColProps' =>
              {
                'Type' =>
                  {
                    'MaxWidth' => 9
                  }
              }
          )

          dirs.each do |d|
            tbl << [
              'Directory',
              "#{d.file_name.encode('utf-8')}",
              "#{ldap_to_ruby_time(d.create_time)}",
              "#{ldap_to_ruby_time(d.last_change)}",
              "#{d.end_of_file}"
            ]
          end

          files.each do |f|
            tbl << [
              'File',
              "#{f.file_name.encode('utf-8')}",
              "#{ldap_to_ruby_time(f.create_time)}",
              "#{ldap_to_ruby_time(f.last_change)}",
              "#{f.end_of_file}"
            ]
          end

          print(tbl.to_s)

          # else
          #   # TODO: Implement dir traversal, at the moment only the Top Level Dir of the share can be listed
          #   remote_dir = tree.open_directory(remote_dir_path)
          #
          #   # Check if remote_dir opened correctly
          #
          #   remote_dir.each { |file|
          #     print("File Name: #{file.file_name} | Create Time: #{file.create_time} | Last Edit: #{file.last_change} |
          #   Size in Bytes: #{file.byte_length}")
          #   }
        end

        def enum_share
          smb_enumshare(nil, nil)
        end

        def connection_successful
          !@status.nil? && @status.name == 'STATUS_SUCCESS'
        end

        def protocol
          @protocol
        end

        def status
          @status
        end

        def path
          @path
        end

        private

        def fix_broken_pipe
          sock = TCPSocket.new @smb_config[:address], 445
          dispatcher = RubySMB::Dispatcher::Socket.new(sock)

          begin
            @client = RubySMB::Client.new(dispatcher, smb1: true, smb2: true, username: @smb_config[:username], password: @smb_config[:password])
            @protocol = @client.negotiate
            @status = @client.authenticate
          rescue => e
            print("Negotiation or Authentication failed with #{e} exception:\n #{e.backtrace}")
          end
        end

        def reset_broken_smb_connection(err_msg)
          print(err_msg)
          fix_broken_pipe
        end

        def expand_file_path(path)
          if path[0].to_s == '~' || path[0..1] == './' || path[0..2] == '../'
            expanded_path = Pathname(File.expand_path(path))

            unless expanded_path.exist?
              print("File at #{expanded_path} does not exist.")
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
            print("File could not be found at either #{unaltered_path} or #{absolute_path}.")
            nil
          end
        end

        # https://www.ruby-forum.com/t/re-microsoft-timestamp-active-directory/65368
        # Converts a 18-digit LDAP/FILETIME to human-readable date
        # Requires a flag to indicate if the epoch time is Windows or Unix
        def ldap_to_ruby_time(ldap, windows_epoch=true)
          # TODO: Figure out a way to determine of timestamp is unix or windows
          # TODO: Rather annoyingly, you can't start a DateTime before 1970/1/1, only a Date. This means there needs to be a way to add the minutes and seconds to a Date and convert it to DateTime
          #
          if windows_epoch
            # The NT time epoch on Windows NT and later refers to the Windows NT system time in (10^-7)s intervals from 0h 1 January 1601.
            base = Date.new(1601, 1, 1)
          else
            # Unix and POSIX measure time as the number of seconds that have passed since 1 January 1970 00:00:00
            base = DateTime.new(1970, 1, 1)
          end

          base += ldap / (60 * 10000000 * 1440)
          base.strftime("%d/%m/%Y %H:%M")
        end
        end
      end
    end
  end

