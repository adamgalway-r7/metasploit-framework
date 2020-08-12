##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/report'
require 'msf/core/modules/shared/smblogic'

class MetasploitModule < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::SMB::Client
  include Msf::Exploit::Remote::SMB::Client::Authenticated
  include Msf::Exploit::Remote::DCERPC

  # Scanner mixin should be near last
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  include Msf::Modules::Shared::SmbLogic

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'SMB Share Enumeration',
      'Description'    => %q{
        This module determines what shares are provided by the SMB service and which ones
        are readable/writable. It also collects additional information such as share types,
        directories, files, time stamps, etc.

        By default, a netshareenum request is done in order to retrieve share information,
        but if this fails, you may also fall back to SRVSVC.
      },
      'Author'         =>
        [
          'hdm',
          'nebulus',
          'sinn3r',
          'r3dy',
          'altonjx'
        ],
      'License'        => MSF_LICENSE,
      'DefaultOptions' =>
        {
          'DCERPC::fake_bind_multi' => false
        }
    ))

    register_options(
      [
        OptBool.new('SpiderShares',      [false, 'Spider shares recursively', false]),
        OptBool.new('ShowFiles',        [true, 'Show detailed information when spidering', false]),
        OptBool.new('SpiderProfiles',  [false, 'Spider only user profiles when share = C$', true]),
        OptEnum.new('LogSpider',      [false, '0 = disabled, 1 = CSV, 2 = table (txt), 3 = one liner (txt)', 3, [0,1,2,3]]),
        OptInt.new('MaxDepth',      [true, 'Max number of subdirectories to spider', 999]),
      ])

    deregister_options('RPORT')
  end

  def run_host(ip)
    smb_enumshare(ip, datastore)
  end
end

