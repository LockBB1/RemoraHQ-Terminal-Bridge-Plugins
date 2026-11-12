# frozen_string_literal: true
require 'tmpdir'
require 'fileutils'
require 'open3'
require 'rbconfig'

# Exercise the real helper with a conflicting default logger and local-only gems.
Dir.mktmpdir('remora-bundle-test-') do |dir|
  gems = {
    'logger' => ['999.0.0', { 'logger.rb' => '' }],
    'winrm' => ['2.4.1', {
      'winrm.rb' => 'module WinRM; module HTTP; class HttpGSSAPI; end; end; module Shells; class Base; end; end; end',
      'winrm/shells/base.rb' => ''
    }],
    'winrm-fs' => ['1.0.0', { 'winrm-fs.rb' => '' }],
    'gssapi' => ['1.0.0', { 'gssapi.rb' => 'module GSSAPI; module LibGSSAPI; end; end', 'gssapi/extensions.rb' => '' }]
  }
  declarations = gems.map do |name, (version, files)|
    root = File.join(dir, name)
    files.each do |file, content|
      path = File.join(root, 'lib', file)
      FileUtils.mkdir_p(File.dirname(path))
      File.write(path, content)
    end
    File.write(File.join(root, "#{name}.gemspec"), "Gem::Specification.new { |s| s.name = '#{name}'; s.version = '#{version}'; s.summary = 'fixture'; s.authors = ['fixture'] }\n")
    "gem '#{name}', path: '#{root.tr('\\', '/')}'"
  end
  gemfile = File.join(dir, 'Gemfile')
  File.write(gemfile, declarations.join("\n") + "\n")
  env = { 'BUNDLE_GEMFILE' => gemfile, 'BUNDLE_PATH' => File.join(dir, 'vendor'),
          'BUNDLE_FROZEN' => 'false', 'BUNDLE_DEPLOYMENT' => 'false', 'BUNDLE_AUTO_INSTALL' => 'false', 'RUBYOPT' => nil }
  FileUtils.cp(File.expand_path('../remote-install/winrm.rb', __dir__), File.join(dir, 'winrm.rb'))
  FileUtils.cp(File.expand_path('../remote-install/gssapi-safety.rb', __dir__), dir)
  helper = File.join(dir, 'winrm.rb')
  stdout, _stderr, status = Open3.capture3(env, RbConfig.ruby, helper, stdin_data: '{}')
  raise (_stderr.include?('already activated logger') ? 'LOGGER_CONFLICT' : 'OTHER_STARTUP_FAILURE') unless status.exitstatus == 1 && stdout.strip == 'ri-result:outcome_unknown'
end
puts 'Bundler startup with a conflicting default logger PASS'
