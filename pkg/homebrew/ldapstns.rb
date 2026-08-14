# SPDX-License-Identifier: BSD-2-Clause
#
# A Homebrew formula for ldapstns.
#
# This is not in homebrew-core and is unlikely ever to be: it is a directory
# service for one particular API, which is not what that collection is for.
# Install it from a tap, or point brew at this file directly:
#
#     brew install --build-from-source ./pkg/homebrew/ldapstns.rb
#
# The source is fetched with git rather than as a release tarball because
# libstns is a submodule, and the tarballs GitHub generates from a tag do not
# contain submodule content.
class Ldapstns < Formula
  desc "Serve an STNS directory to macOS Open Directory over LDAPv3"
  homepage "https://github.com/zakinko/ldapstns"
  url "https://github.com/zakinko/ldapstns.git", tag: "v0.1.0"
  license "BSD-2-Clause"
  head "https://github.com/zakinko/ldapstns.git", branch: "main"

  # opendirectoryd, dsconfigldap and launchd are the whole point of this
  # program; there is nothing here for any other system to run.
  depends_on :macos

  def install
    system "make", "PREFIX=#{prefix}", "SYSCONFDIR=#{etc}", "install"
  end

  def post_install
    (etc/"stns/client").mkpath
  end

  def caveats
    <<~EOS
      Configure the API client first, then the daemon:

        cp #{opt_pkgshare}/../examples/ldapstns/stns.conf #{etc}/stns/client/stns.conf
        $EDITOR #{etc}/stns/client/stns.conf

      Then start it.  Under "brew services" the daemon binds port 389 itself
      and needs root to do it, which is why this one wants sudo:

        sudo brew services start ldapstns

      To have launchd open the socket instead - so the daemon never runs as
      root at all - install the job description shipped with it and skip
      "brew services" entirely:

        sudo cp #{opt_prefix}/share/ldapstns/jp.stns.ldapstns.plist /Library/LaunchDaemons/
        sudo launchctl bootstrap system /Library/LaunchDaemons/jp.stns.ldapstns.plist

      Either way, point Open Directory at it once it is running:

        sudo dsconfigldap -a 127.0.0.1
        dscl /LDAPv3/127.0.0.1 -list /Users

      See ldapstns(8) and ldapstns.conf(5).
    EOS
  end

  # Binding port 389 needs root; the daemon gives it up as soon as it has.
  service do
    run [opt_bin/"ldapstns"]
    keep_alive successful_exit: false
    require_root true
  end

  test do
    (testpath/"ldapstns.conf").write <<~EOS
      listen = "127.0.0.1"
      port   = 11389
      suffix = "dc=test"
    EOS
    (testpath/"stns.conf").write <<~EOS
      api_endpoint = "http://127.0.0.1:1104/v1"
      cache = false
    EOS
    # -n parses both files and prints what it made of them without opening a
    # socket or contacting the API, which is as much as a test with no server
    # to talk to can honestly check.
    (etc/"stns/client").mkpath
    cp testpath/"stns.conf", etc/"stns/client/stns.conf"
    assert_match "configuration ok", shell_output("#{bin}/ldapstns -n -f #{testpath}/ldapstns.conf")
    assert_match version.to_s, shell_output("#{bin}/ldapstns -v")
  end
end
