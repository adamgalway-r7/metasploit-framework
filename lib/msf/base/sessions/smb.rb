# -*- coding: binary -*-

require 'msf/base'
require 'msf/base/sessions/scriptable'
require 'rex/post/smb'

module Msf
module Sessions

###
#
# This class provides an interactive session with a hardware bridge.
# The hardware bridge must support the current API supported by Metasploit.
#
###
class SMB < Rex::Post::SMB::Client

  #
  # This interface supports basic interaction.
  #
  include Msf::Session::Basic

  include Msf::Session::Interactive

  #
  # Initialize the HWBridge console
  #
  def initialize(connection, opts={})
    super
    #
    #  The module will manage it's alive state
    #
    self.alive = true

    #
    # Initialize the smb client
    #
    self.init_smb(connection, opts)

    #
    # Create the console instance
    #
    self.console = Rex::Post::SMB::Ui::Console.new(self)
  end

  #
  # Returns the type of session.
  #
  def self.type
    'smb'
  end

  #
  # Returns the session description.
  #
  def desc
    "SMB Session interface"
  end

  #
  # We could tie this into payload UUID
  #
  def platform
    "hardware"
  end

  #
  # We could tie this into payload UUID
  #
  def arch
    ARCH_CMD
  end

  #
  # Session info based on the type of hw bridge we are connected to
  # This information comes after connecting to a bridge and pulling status info
  #
  def info
    unless exploit.nil?
      exploit.info
    end
  end

  ##
  # :category: Msf::Session::Interactive implementors
  #
  # Initializes the console's I/O handles.
  #
  def init_ui(input, output)
    self.user_input = input
    self.user_output = output
    console.init_ui(input, output)
    console.set_log_source(log_source)

    super
  end

  ##
  # :category: Msf::Session::Interactive implementors
  #
  # Resets the console's I/O handles.
  #
  def reset_ui
    console.unset_log_source
    console.reset_ui
  end


  ##
  # :category: Msf::Session::Interactive implementors
  #
  # Interacts with the hwbridge client at a user interface level.
  #
  def _interact
    framework.events.on_session_interact(self)
    # Call the console interaction subsystem of the meterpreter client and
    # pass it a block that returns whether or not we should still be
    # interacting.  This will allow the shell to abort if interaction is
    # canceled.
    console.interact { self.interacting != true }

    # If the stop flag has been set, then that means the user exited.  Raise
    # the EOFError so we can drop this handle like a bad habit.
    raise EOFError if (console.stopped? == true)
  end

  def alive?
    self.alive
  end

  #
  # Calls the class method.
  #
  def type
    self.class.type
  end

  #
  # The shell will have been initialized by default.
  #
  def shell_init
    return true
  end

  attr_accessor :console # :nodoc:
  attr_accessor :alive # :nodoc:
  attr_accessor :api_version
  attr_accessor :fw_version
  attr_accessor :hw_version
  attr_accessor :device_name
private
  attr_accessor :rstream # :nodoc:

end

end
end
