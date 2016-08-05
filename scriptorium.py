#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#Plugin for providing an errbot interface to Scriptorium

from errbot import BotPlugin, botcmd
from errbot import utils
from errbot.templating import tenv
from Crypto.PublicKey import RSA
import tempfile
import subprocess
import os
import re

CONFIG_TEMPLATE = {
  'SCRIPTORIUM_LOCATION': os.path.join(os.environ['HOME'], 'scriptorium'),
  'MMD': '/usr/local/bin/multimarkdown'
}

class Scriptorium(BotPlugin):
    REQUIRED_PACKAGES = ['multimarkdown', 'pdflatex', 'latexpand', 'biber']
    def _check_requirements(self):
        """Checks that the proper binaries and folders exist for operation."""
        if not os.path.isdir(self.config['SCRIPTORIUM_LOCATION']):
            raise RuntimeError("Scriptorium does not exist at {0}".format(self.config['SCRIPTORIUM_LOCATION']))

        #Multimarkdown installs to /usr/local/bin by default, make sure it's in the path for this test
        old_path = None
        if os.environ['PATH'].find('/usr/local/bin') == -1:
            old_path = os.environ['PATH']
            os.environ['PATH'] = '/usr/local/bin:{0}'.format(old_path)

        status = True
        for ii in Scriptorium.REQUIRED_PACKAGES:
            location = utils.which(ii)

            if location is None:
                self.log.error('Could not find executable {0}'.format(ii))
                status = False

        #If path was modified, reset it for minimal impact.
        if old_path:
            os.environ['PATH'] = old_path
        if not status:
            raise RuntimeError("Could not find required binaries.")

    def _is_repo(self, path):
      """Tests if a given path is a folder containing a git repository."""
      return os.path.isdir(path) and os.path.isdir(os.path.join(path, '.git'))

    def _write_key(self, key):
        """Writes the key to a temporary file, returns path if successful."""
        fd, path = tempfile.mkstemp()
        with open(fd, 'w') as fdkey:
            fdkey.write(key.exportKey('PEM').decode('ascii'))

        return path

    def _validate_remote(self, url):
        """Checks the fingerprint of the remote host and stores it."""
        value = subprocess.call(['ssh-keygen', '-F', url])
        if value == 0:
            return True
        try:
            key = subprocess.check_output(['ssh-keyscan', '-H', url], universal_newlines=True)
            if key:
              known_hosts = os.path.expanduser(os.path.join("~", ".ssh", "known_hosts"))
              with open(known_hosts, 'a') as fd:
                fd.write(key)
        except:
          return False

    def _run_git_remote_cmd(self, cmd, cwd=None, key=None):
        """Executes a git command with an SSH key set."""
        path = self._write_key(key) if key else ''
        env = {'GIT_SSH_COMMAND': 'ssh -i {0}'.format(path)} if key else None
        try:
            subprocess.check_output(cmd, cwd=cwd, env=env)
        except subprocess.CalledProcessError as e:
            raise e
        finally:
            if path:
                os.remove(path)

    def _get_branch_name(self, path):
        if not self._is_repo(path):
            return ""
        try:
            return str(subprocess.check_output(['git', 'symbolic-ref', '--short', 'HEAD'], cwd=path, universal_newlines=True))
        except:
            return ""

    def _is_repo_clean(self, path):
        if not self._is_repo(path):
            return False

        try:
            status = subprocess.check_output(['git', 'status', '--porcelain'], cwd=path)
            return bool(status)
        except:
            return False

    def _test_remote_access(self, path, user = None):
        try:
            key = self.get('users', {}).get(user, {}).get('key', None)
            self._run_git_remote_cmd(['git', 'fetch'], cwd=path, key=key)
            return True
        except subprocess.CalledProcessError as e:
            return False

    def _clone_repo(self, url, path, user = None):
        """Clones a git repository from the url to a folder inside the path given."""
        try:
            self.log.debug("Cloning {0} to {1}".format(url, path))
            cmd = ['git', 'clone', url]
            key = self.get('users', {}).get(user, {}).get('key', None)
            self._run_git_remote_cmd(cmd, cwd=path, key=key)
            return True
        except subprocess.CalledProcessError as e:
          cmd_str = ' '.join(cmd)
          self.log.error("git clone command \"{0}\" failed: {1}".format(cmd_str, e.output))
          return False

    def _update_repo(self, path, force=False, commit=None, user=None):
        """Updates a repository to a particular version, or the latest version if commit is None."""

        if not self._is_repo(path):
            return False

        key = self.get('users', {}).get(user, {}).get('key', None)
        try:
            self._run_git_remote_cmd(['git', 'fetch'])
            subprocess.check_call()
            cmd = ['git', 'checkout']

            if force:
                cmd.append('--force')
            if commit:
                cmd.append(commit)

            self._run_git_remote_cmd(cmd, cwd=path, key=key)
            return True
        except:
            return False

    def _parse_repo_url(self, path):
        """Parses a string, attempting to find a folder.git extension at the end."""
        url_re = re.compile(r'((git|ssh|http(s)?)(:(//)?)|([\w\d]*@))?(?P<url>[\w\.]+).*\/(?P<dir>[\w\-]+)(\.git)(/)?')
        match = url_re.search(path)
        return (match.group('url'), match.group('dir')) if match else (None, None)

    def _build_paper(self, path):
        """Builds paper using a fairly rigid command order, to mitigate security concerns for running arbitrary code."""
        self.log.debug("Attempting to build paper in {0}".format(path))
        paper_path = os.path.join(path, 'paper.mmd')

        if not os.path.exists(paper_path):
            return None

        subprocess.check_output([os.path.join(self.config['SCRIPTORIUM_LOCATION'], 'bin', 'make_paper.sh'), path], universal_newlines=True, cwd=path)
        return os.path.join(path, 'paper.pdf')

    @botcmd
    def paper_add(self, mess, args):
        """Adds a paper to the repository of papers."""
        self._check_requirements()

        host, folder = self._parse_repo_url(args)

        if host:
            self._validate_remote(host)
        if folder is None:
            return "Cannot parse URL for repository folder name."

        papers_dir = os.path.join(self.config['SCRIPTORIUM_LOCATION'], 'papers')
        paper_dir = os.path.join(papers_dir, folder)

        if os.path.exists(paper_dir):
            return "{0} already exists in the papers folder, refusing to overwrite.".format(folder)

        if self._clone_repo(args, papers_dir, user=mess.frm.username):
            return "Downloaded paper repository {0}".format(folder)
        else:
            return "Could not download specified paper repository."

    @botcmd
    def paper_update(self, mess, args):
        """Updates a paper to the specified version."""
        self._check_requirements()

        paper_dir = os.path.join(self.config["SCRIPTORIUM_LOCATION"], 'papers', args)
        if not self._is_repo(paper_dir):
            return "{0} is not a valid paper.".format(args)
        if not self._test_remote_access(paper_dir, mess.frm.username):
            return "You do not have permissions to access this paper."
        if self._update_repo(paper_dir, user=mess.frm.username):
            return "{0} has been updated to the latest version.".format(args)

    @botcmd
    def paper_make(self, mess, args):
        """Attempts to make a paper, and returns the PDF if successful."""
        self._check_requirements()

        paper_dir = os.path.join(self.config['SCRIPTORIUM_LOCATION'], 'papers', args)
        if not self._is_repo(paper_dir):
            return "I cannot find a paper named {0}.".format(args)
        if not self._test_remote_access(paper_dir, mess.frm.username):
            return "You do not have permissions to access this paper."

        yield "Attempting to make {0}".format(args)
        try:
            pdf_path = self._build_paper(paper_dir)
            if pdf_path:
                data = {'filename': 'paper.pdf', 'file': open(pdf_path, 'rb'), 'channels': mess.frm.channelid}
                self._bot.api_call('files.upload', data)
        except subprocess.CalledProcessError as e:
            yield "Failed to make {0}.".format(args)
            self.send(self.build_identifier(mess.frm.username), e.output)

    @botcmd
    def template_add(self, mess, args):
        """Command to add a template to the Scriptorium setup."""
        self._check_requirements()

        host, folder = self._parse_repo_url(args)

        if host:
            self._validate_remote(host)

        if folder is None:
          return "Cannot parse URL for repository folder name."

        templates_dir = os.path.join(self.config['SCRIPTORIUM_LOCATION'], 'templates')
        template_path = os.path.join(templates_dir, folder)
        if os.path.exists(template_path):
            return "Refusing to overwrite template {0}".format(folder)

        if self._clone_repo(args, templates_dir, user=mess.frm.username):
            return "Successfully installed template repository {0}".format(args)
        else:
            return "Failed to clone template repository {0}".format(args)

    @botcmd
    def template_list(self, mess, args):
        """List all currently installed templates."""
        self._check_requirements()

        templates_dir = os.path.join(self.config["SCRIPTORIUM_LOCATION"], 'templates')
        templates = [ii for ii in os.listdir(templates_dir) if self._is_repo(os.path.join(templates_dir, ii))]
        return "`# Installed Templates\n" + '\n'.join(["* {0}".format(ii) for ii in templates]) + '`'

    @botcmd(template="template_info")
    def template_info(self, mess, args):
        """Get information about the status of the requested template."""
        self._check_requirements()
        template_dir = os.path.join(self.config["SCRIPTORIUM_LOCATION"], 'templates', args)
        if not self._is_repo(template_dir):
          return {'name': args, 'branch': "None", 'status': 'Not installed'}

        status = 'clean' if self._is_repo_clean(template_dir) else 'dirty'
        return {'name': args, 'branch': self._get_branch_name(template_dir), 'status': status}

    @botcmd
    def template_update(self, mess, args):
        """Updates the template to the latest version."""
        self._check_requirements()

        template_dir = os.path.join(self.config["SCRIPTORIUM_LOCATION"], 'templates', args)
        if not self._is_repo(template_dir):
            return "{0} is not a valid template.".format(args)
        if self._update_repo(template_dir, user=mess.frm.username):
            return "{0} has been updated to the latest version.".format(args)

    @botcmd
    def key_get(self, mess, args):
        """Generates or returns an SSH public key for allowing the bot to access private repositories."""
        users = self['users'] if 'users' in self else {}
        if mess.frm.username not in users:
            self.log.debug('Adding user {0}'.format(mess.frm.username))
            users[mess.frm.username] = {'key': RSA.generate(2048)}
        user_info = users[mess.frm.username]
        if 'key' not in user_info:
          user_info['key'] = RSA.generate(2048)
          users[mess.frm.username] = user_info
        self['users'] = users
        ssh_pub_key = user_info['key'].publickey().exportKey('OpenSSH').decode("utf-8")
        return "Your public key to grant me access to repositories is:\n{0}".format(ssh_pub_key)

    @botcmd
    def key_rm(self, mess, args):
        """Removes the key for the user requesting the operation."""
        users = self['users'] if 'users' in self else {}

        if mess.frm.username not in users:
            return "You do not appear to have an SSH key generated."
        users[mess.frm.username].pop('key', None)

        self['users'] = users

        return "Keys deleted."

    def get_configuration_template(self):
        """Defines the configuration structure this plugin supports

        You should delete it if your plugin doesn't use any configuration like this"""
        return CONFIG_TEMPLATE

    def configure(self, configuration):
        if configuration is not None and configuration != {}:
            config = dict(chain(CONFIG_TEMPLATE.items(),
                                configuration.items()))
        else:
            config = CONFIG_TEMPLATE
        super().configure(config)
