# frozen_string_literal: true
# WinRM 2.4.1 does not check these FFI return values; never send unsealed SOAP.
module RemoraGssapiSafety
  def gss_wrap_iov(*arguments)
    status = super
    raise 'winrm_encryption_failed' unless status.zero? && arguments.fetch(4).read_int == 1

    status
  end

  def gss_unwrap_iov(*arguments)
    status = super
    raise 'winrm_decryption_failed' unless status.zero? && arguments.fetch(2).read_int == 1

    status
  end
end
GSSAPI::LibGSSAPI.singleton_class.prepend(RemoraGssapiSafety)

# WinRM's 401 path otherwise resends the same SOAP independently of retry_limit.
module RemoraSingleKerberosContext
  private

  def init_krb
    raise 'winrm_authentication_lost' if @remora_kerberos_initialized

    @remora_kerberos_initialized = true
    super
  end
end
WinRM::HTTP::HttpGSSAPI.prepend(RemoraSingleKerberosContext)

# Base#with_command_shell otherwise recreates a shell and repeats the command on faults.
module RemoraNoShellReplay
  private

  def reset_on_error(_error)
    raise 'winrm_command_interrupted'
  end
end
WinRM::Shells::Base.prepend(RemoraNoShellReplay)

# Base#run cleans up in ensure before returning the completed response.
module RemoraCommandCleanupSafety
  attr_reader :remora_command_cleanup_failed

  private

  def cleanup_command(command_id)
    super
  rescue StandardError
    @remora_command_cleanup_failed = true
  end
end
WinRM::Shells::Base.prepend(RemoraCommandCleanupSafety)
