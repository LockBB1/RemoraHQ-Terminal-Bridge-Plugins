# frozen_string_literal: true
require 'tmpdir'
require 'fileutils'
require 'open3'
require 'rbconfig'
require 'json'

Dir.mktmpdir('remora-diag-test-') do |dir|
  FileUtils.cp(File.expand_path('../remote-install/winrm.rb', __dir__), File.join(dir, 'winrm.rb'))
  FileUtils.cp(File.expand_path('../remote-install/gssapi-safety.rb', __dir__), dir)
  shim = <<~'RUBY'
    require 'json'; require 'logger'; require 'open3'; require 'fileutils'
    module Kernel
      alias diagnostic_original_require require
      def require(name)
        return true if %w[bundler/setup winrm winrm-fs winrm/shells/base gssapi gssapi/extensions].include?(name)
        diagnostic_original_require(name)
      end
    end
    spec = Gem::Specification.new { |s| s.name = 'winrm'; s.version = '2.4.1' }
    Gem.loaded_specs['winrm'] = spec
    module Open3
      def self.capture3(*) = ['', '', Struct.new(:success?).new(true)]
    end
    module GSSAPI; module LibGSSAPI; end; end
    module WinRM
      module HTTP; class HttpGSSAPI; end; end
      module Shells; class Base; end; end
      module FS
        class FileManager
          def initialize(*) = nil
          def upload(*)
            raise 'private upload error' if ENV['RI_TEST_CASE'] == 'upload'
          end
        end
      end
      class Connection
        def initialize(*) = nil
        def shell(*)
          shell = Object.new
          def shell.run(command)
            if command.include?("-Action 'create'")
              text = 'ri-directory:C:\\ProgramData\\RemoraHQ-Diagnostic-' + ('a' * 32) + '\\installer.exe'
            elsif command.include?("-Action 'remove'")
              raise 'private cleanup error' if ENV['RI_TEST_CASE'] == 'cleanup'
              text = 'ri-directory:removed'
            else
              text = 'ri-diagnostic:match:valid:present'
            end
            Struct.new(:stdout, :exitcode).new(text, 0)
          end
          yield shell
        end
      end
    end
  RUBY
  shim_path = File.join(dir, 'shim.rb')
  File.write(shim_path, shim)
  job = { username: 'fixture@EXAMPLE.INVALID', password: 'synthetic', host: 'fixture.example.invalid',
          cacheDirectory: dir, mode: 'diagnostic', operationId: 'a' * 32, installerSha256: 'a' * 64,
          localExe: 'fixture', script: 'fixture', directoryScript: 'fixture' }.to_json
  { 'ok' => [0, 'ri-diagnostic:match:valid:present:confirmed'],
    'cleanup' => [0, 'ri-diagnostic:match:valid:present:unknown'],
    'upload' => [1, 'ri-result:outcome_unknown'] }.each do |mode, (code, marker)|
    env = { 'RUBYOPT' => "-r#{shim_path.tr('\\', '/')}", 'RI_TEST_CASE' => mode }
    stdout, stderr, status = Open3.capture3(env, RbConfig.ruby, File.join(dir, 'winrm.rb'), stdin_data: job)
    raise 'diagnostic transport result failed' unless status.exitstatus == code && stdout.lines.map(&:strip).include?(marker) && stderr.empty? && !stdout.include?('private')
  end
end
puts 'Diagnostic upload and cleanup outcomes PASS'
