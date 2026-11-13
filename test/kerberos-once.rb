# frozen_string_literal: true
require 'base64'
require 'logger'

# Execute the pinned gem's real send_request, replacing only external boundaries.
transport = ENV['REMORA_WINRM_TRANSPORT'] || File.join(Gem::Specification.find_by_name('winrm', '= 2.4.1').full_gem_path, 'lib/winrm/http/transport.rb')
$LOADED_FEATURES << 'httpclient.rb'
$LOADED_FEATURES << File.join(File.dirname(transport), 'response_handler.rb')
load transport
base = File.expand_path('../shells/base.rb', File.dirname(transport))
%w[retryable ../http/transport ../wsmv/cleanup_command ../wsmv/close_shell ../wsmv/command ../wsmv/command_output ../wsmv/receive_response_reader ../wsmv/create_shell ../wsmv/soap].each do |dependency|
  $LOADED_FEATURES << File.expand_path(dependency + '.rb', File.dirname(base))
end
module WinRM
  class WinRMWSManFault < StandardError
    def fault_code = '2150858843'
  end
  module Shells
    module Retryable; end
  end
end
load base
module GSSAPI
  module LibGSSAPI; end
  class Simple
    def initialize(*) = nil
    def init_context(*) = 'synthetic token'
  end
end
require_relative '../remote-install/gssapi-safety'

client = WinRM::HTTP::HttpGSSAPI.allocate
client.instance_variable_set(:@endpoint, Struct.new(:host).new('fixture.example.invalid'))
client.instance_variable_set(:@service, 'HTTP/fixture.example.invalid@EXAMPLE.INVALID')
client.instance_variable_set(:@logger, Logger.new(File::NULL, level: Logger::FATAL))
http = Object.new
handshakes = 0
http.define_singleton_method(:post) do |*|
  handshakes += 1
  Struct.new(:header).new({ 'WWW-Authenticate' => ['Kerberos ' + Base64.strict_encode64('synthetic')] })
end
client.instance_variable_set(:@httpcli, http)
client.send(:init_krb)
requests = 0
client.define_singleton_method(:send_kerberos_request) do |_message|
  requests += 1
  Struct.new(:status).new(401)
end
begin
  client.send_request('synthetic command, no network')
  raise '401 was accepted'
rescue RuntimeError => error
  raise unless error.message == 'winrm_authentication_lost'
end
raise 'SOAP was retried' unless requests == 1 && handshakes == 1
puts 'Pinned WinRM 2.4.1 401: one SOAP request, no reauthentication/replay PASS (synthetic HTTP/GSSAPI)'

shell = WinRM::Shells::Base.allocate
shell.instance_variable_set(:@shell_id, 'synthetic')
commands = 0
shell.define_singleton_method(:send_command) do |*|
  commands += 1
  raise WinRM::WinRMWSManFault
end
begin
  shell.send(:with_command_shell, 'synthetic') { raise 'unexpected command completion' }
  raise 'fault was accepted'
rescue RuntimeError => error
  raise unless error.message == 'winrm_command_interrupted'
end
raise 'command was retried' unless commands == 1
puts 'Pinned WinRM 2.4.1 WSMan shell reset: one command, no replay PASS (synthetic command fault)'

# Exercise Base#run's real ensure after read_output, rather than mocking shell.run.
module WinRM
  class WinRMHTTPTransportError < StandardError; end
  module WSMV
    class CleanupCommand
      def initialize(*) = nil
      def build = 'synthetic cleanup'
    end
  end
end
[:completed, :receive_error].each do |scenario|
  shell = WinRM::Shells::Base.allocate
  shell.instance_variable_set(:@shell_id, 'synthetic')
  shell.instance_variable_set(:@logger, Logger.new(File::NULL, level: Logger::FATAL))
  transport = Object.new
  transport.define_singleton_method(:send_request) { |*| raise 'synthetic_cleanup_error' }
  shell.instance_variable_set(:@transport, transport)
  commands = 0
  shell.define_singleton_method(:send_command) { |*| commands += 1; 'synthetic' }
  shell.define_singleton_method(:command_output_message) { |*| 'synthetic' }
  expected = Struct.new(:stdout, :exitcode).new("ri-result:installer_completed\r\nri-cleanup:confirmed\r\n", 0)
  reader = Object.new
  reader.define_singleton_method(:read_output) do |*|
    raise 'synthetic_receive_error' if scenario == :receive_error

    expected
  end
  shell.define_singleton_method(:response_reader) { reader }
  if scenario == :completed
    raise 'Completed response was replaced' unless shell.run('synthetic') == expected
  else
    begin
      shell.run('synthetic')
      raise 'Incomplete read was accepted'
    rescue RuntimeError => error
      raise unless error.message == 'synthetic_receive_error'
    end
  end
  raise 'Command cleanup failure was hidden' unless shell.remora_command_cleanup_failed
  raise 'Command was replayed after cleanup failure' unless commands == 1
end
puts 'Pinned WinRM 2.4.1 inner cleanup: preserve completed response and receive failure, no replay PASS'
