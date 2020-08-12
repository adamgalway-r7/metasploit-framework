##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/base/sessions/smb'
require 'rex/post/smb/connection'

class MetasploitModule < Msf::Auxiliary

  def initialize(info={})
    super( update_info( info, {
        'Name'          => 'SMB Session Connector',
        'Description'   => %q{
          Exploit Module used to connect to SMB servers.
        },
        'License'       => MSF_LICENSE,
        'Author'        =>
          [
            'agalway-r7'
          ],
        'Session'       => Msf::Sessions::SMB,
        'SessionTypes'  => [ 'smb' ], #TODO Implement this
        'References'    =>
          [
            [ 'URL', 'http://jim.bob' ]  # TODO Add in link to docs
          ]
      }
      ))
    register_options(
      [
        Opt::RHOST('192.168.1.153'),
        OptString.new('USERNAME', [ true, "Username"]),
        OptString.new('PASSWORD', [ true, "Password"]),
        OptString.new('SHARE',    [ true, "Share Path"])
      ],
      self.class
    )
    @last_access = nil
  end

  def run
    conn = Rex::Post::SMB::Connection.new(
      {
        address: datastore['RHOST'],
        username: datastore['USERNAME'],
        password: datastore['PASSWORD'],
        share: datastore['SHARE']
      }
    )

    if conn.connection_successful
      sess = Msf::Sessions::SMB.new(
        conn
      )

      sess.set_from_exploit(self)
      framework.sessions.register(sess)

      @protocol = conn.protocol
      @path = conn.path

      print_good("Connection to #{conn.path} succeeded.")
      print_good("Protocol: #{conn.protocol}")
      print_good("Status: #{conn.status}")
    else
      print_error("Connection to #{conn.path} failed.")
      print_error("Protocol: #{conn.protocol}")
      print_error("Status: #{conn.status}")
    end
  end

  def info
    "#{@protocol}: #{@path}"
  end
end
