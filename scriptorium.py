#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#Plugin for providing an errbot interface to Scriptorium

from errbot import BotPlugin, botcmd
from errbot import utils
from errbot.templating import tenv
from Crypto.PublicKey import RSA
import shutil
import tempfile
import subprocess
import os
import re
from itertools import chain
from contextlib import contextmanager
import scriptorium
import pymmd
import pygit2

CONFIG_TEMPLATE = {
  'SCRIPTORIUM_LOCATION': os.path.join(os.environ['HOME'], 'scriptorium')
}

def _is_repo_clean(repo):
    return len(repo.status()) == 0 if repo else False

class Scriptorium(BotPlugin):
    def _check_requirements(self):
        """Checks that the proper binaries and folders exist for operation."""
        if not os.path.isdir(self.config['SCRIPTORIUM_LOCATION']):
            raise RuntimeError("Scriptorium does not exist at {0}".format(self.config['SCRIPTORIUM_LOCATION']))
        if not pymmd.valid_mmd():
            raise RuntimeError('pymmd is not properly configured')

    @contextmanager
    def _credentials(self, user):
        key = self.get('users', {}).get(user, {}).get('key', None)
        cred = None
        if key is not None:
            priv_key, pub_key, path = self._write_keys(key)
            cred = pygit2.Keypair(user, pub_key, priv_key, '')
        mycb = pygit2.RemoteCallbacks()
        if cred:
            mycb.credentials = cred
        yield mycb
        shutil.rmtree(path)

    @contextmanager
    def _remote(self, repo, remote_name='origin', user=os.getlogin()):
        for remote in repo.remotes:
            if remote.name != remote_name:
                continue
            with self._credentials(user) as cred:
                yield remote, mycb
            break

    def _write_keys(self, key):
        """Writes the key to a temporary file, returns path if successful."""
        path = tempfile.mkdtemp()
        priv_key = os.path.join(path, 'id_rsa')
        pub_key = os.path.join(path, 'ida_rsa.pub')
        with open(priv_key, 'w') as fdkey:
            fdkey.write(key.exportKey('PEM').decode('ascii'))
        with open(pub_key, 'w') as fdkey:
            fdkey.write(key.publickey().exportKey('PEM').decode('ascii'))

        return priv_key, pub_key, path

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
            return True
        except:
          return False

    def _get_branch_name(self, path):
        repo = pygit2.Repository(path)
        return repo.head.shorthand if repo else None

    def _test_remote_access(self, path, user=os.getlogin(), remote_name='origin'):
        try:
            repo = pygit2.Repository(path)
            with self._remote(repo, user=user) as remote, callbacks:
                remote.fetch(callbacks=callbacks)
                return True
        except pygit2.GitError as exc:
            return False

    def _clone_repo(self, url, path, user=os.getlogin()):
        """Clones a git repository from the url to a folder inside the path given."""
        try:
            self.log.debug("Cloning {0} to {1}".format(url, path))
            with self._credentials(user) as cred:
                if cred:
                    pygit2.clone_repository(url, path, callbacks=cred)

    def _update_repo(self, repo, force=False, remote_name='origin', user=os.getlogin()):
        """Updates a repository to a particular version, or the latest version if commit is None."""

        with self._remote(repo, remote_name, user) as remote, callbacks:
            remote.fetch(callbacks=callbacks)
            bname = repo.head.shorthand
            remote_refname = 'refs/remotes/{0}/{1}'.format(remote_name, bname)
            remote_master_id = repo.lookup_reference(remote_refname).target
            merge_result, _ = repo.merge_analysis(remote_master_id)
            if merge_result & pygit2.GIT_MERGE_ANALYSIS_FASTFORWARD:
                repo.checkout_tree(repo.get(remote_master_id))
                master_ref = repo.lookup_reference('refs/head/{0}'.format(bname))
                master_ref.set_target(remote_master_id)
                repo.head.set_target(remote_master_id)
            elif merge_result & pygit2.MERGE_ANALYSIS_NORMAL and force:
                repo.checkout_tree(remote_master_id, strategy=pygit2.GIT_CHECKOUT_FORCE)

    def _parse_repo_url(self, path):
        """Parses a string, attempting to find a folder.git extension at the end."""
        url_re = re.compile(r'((git|ssh|http(s)?)(:(//)?)|(?P<user>[\w\d]*)@)?(?P<url>[\w\.]+).*\/(?P<dir>[\w\-]+)(\.git)(/)?')
        match = url_re.search(path)
        if not match:
            return None

        user = match.group('user') if match.group('user') else os.getlogin()

        return {'url' : match.group('url'),
                    'dir': match.group('dir'),
                    'user': user}

    @botcmd
    def validate(self, _, args):
        return str(self._validate_remote(args))

    @botcmd
    def paper_add(self, mess, args):
        """Adds a paper to the repository of papers."""
        self._check_requirements()

        remote_info = self._parse_repo_url(args)

        if not remote_info:
            return "Cannot parse URL for repository info."

        if host:
            self._validate_remote(remote_info['url'])

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
            pdf_path = scriptorium.to_pdf(paper_dir, use_shell_escape=True)
            if pdf_path:
                self.log.debug('Paper built in {0}, sending to {1}'.format(paper_dir, mess.frm.channelid))
                self.send_stream_request(mess.frm, open(pdf_path, 'rb'), name="paper.pdf", stream_type='application/pdf')
                self.log.debug('Stream requested to send paper.')
        except subprocess.CalledProcessError as e:
            yield "Failed to make {0}.".format(args)
            self.send(self.build_identifier(mess.frm.username), e.output)

    @botcmd
    def paper_rm(self, mess, args):
        """Deletes a paper from the system."""
        self._check_requirements()

        paper_dir = os.path.join(self.config["SCRIPTORIUM_LOCATION"], 'papers', args)
        if not self._is_repo(paper_dir):
            return "{0} is not a valid paper.".format(args)
        if not self._test_remote_access(paper_dir, mess.frm.username):
            return "You do not have permissions to access this paper."

        shutil.rmtree(paper_dir)
        return "Paper successfully removed"

    @botcmd
    def paper_list(self, mess, args):
        """List all papers which a user can interact with."""
        self._check_requirements()

        papers_dir = os.path.join(self.config["SCRIPTORIUM_LOCATION"], 'papers')

        papers = []
        for ii in os.listdir(papers_dir):
          paper_dir = os.path.join(papers_dir, ii)
          if self._is_repo(paper_dir) and os.path.isdir(paper_dir) and self._test_remote_access(paper_dir, mess.frm.username):
            papers.append(ii)

        return "# Installed Paper Repos\n" + '\n'.join(["* {0}".format(ii) for ii in papers])

    @botcmd
    def template_add(self, mess, args):
        """Command to add a template to the Scriptorium setup."""
        self._check_requirements()

        host, folder = self._parse_repo_url(args)

        if not host:
            return "Invalid host {0}".format(args)
        if not self._validate_remote(host):
            return "You do not appear to have permission to access {0}".format(args)

        scriptorium.install_template(args)

    @botcmd
    def template_list(self, mess, args):
        """List all currently installed templates."""
        self._check_requirements()

        templates = scriptorium.all_templates()

        return "# Installed Templates\n" + '\n'.join(["* {0}".format(ii) for ii in templates])

    @botcmd(template="template_info")
    def template_info(self, mess, args):
        """Get information about the status of the requested template."""
        self._check_requirements()
        template_dir = scriptorium.find_template(args)
        with self._repo(template_dir, user=mess.frm.username) as repo:
            if not repo:
                return {'name': args, 'branch': "None", 'status': 'Not installed'}
            status = 'clean' if _is_repo_clean(repo) else 'dirty'
            return {'name': args, 'branch': repo.head.shorthand, 'status': status}

    @botcmd
    def template_update(self, mess, args):
        """Updates the template to the latest version."""
        self._check_requirements()

        template_dir = scriptorium.find_template(args)
        if not template_dir or not self._is_repo(template_dir):
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
