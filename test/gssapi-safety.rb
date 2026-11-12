# frozen_string_literal: true
# Only the FFI boundary is replaced; Ruby dispatch executes the production guard.
module GSSAPI
  module LibGSSAPI
    class << self
      attr_accessor :status
      def gss_wrap_iov(*) = status
      def gss_unwrap_iov(*) = status
    end
  end
end
module WinRM
  module Shells
    class Base; end
  end
  module HTTP
    class HttpGSSAPI; end
  end
end
require_relative '../remote-install/gssapi-safety'
Pointer = Struct.new(:value) { def read_int = value }
checks = 0
%i[gss_wrap_iov gss_unwrap_iov].each do |method|
  [[0, 1, true], [1, 1, false], [0, 0, false]].each do |status, encrypted, success|
    GSSAPI::LibGSSAPI.status = status
    arguments = Array.new(6)
    arguments[method == :gss_wrap_iov ? 4 : 2] = Pointer.new(encrypted)
    begin
      result = GSSAPI::LibGSSAPI.public_send(method, *arguments)
      raise 'guard accepted unsafe GSSAPI result' unless success && result == 0
    rescue RuntimeError => error
      raise if success || !%w[winrm_encryption_failed winrm_decryption_failed].include?(error.message)
    end
    checks += 1
  end
end
puts "GSSAPI guard #{checks}/#{checks} PASS (synthetic FFI)"
