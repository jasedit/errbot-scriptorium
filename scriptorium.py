#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#Plugin for providing an errbot interface to Scriptorium

from errbot import BotPlugin, botcmd
from errbot import utils
from errbot.templating import tenv
import subprocess
import os
import sys
import re

CONFIG_TEMPLATE = {
  'SCRIPTORIUM_LOCATION': os.path.join(os.environ['HOME'], 'scriptorium'),
  'MMD': '/usr/local/bin/multimarkdown'
}

class PaperInfo:
  """Class holding information about a paper which can be built."""
  def __init__(self):
    self.location = None
    self.users = []
    self.use_biber = True

class Scriptorium(BotPlugin):
    REQUIRED_PACKAGES = ['multimarkdown', 'pdflatex', 'latexpand']
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

    def _clone_repo(self, url, path):
        """Clones a git repository from the url to a folder inside the path given."""
        try:
            self.log.debug("Cloning {0} to {1}".format(url, path))
            cmd = ['git', 'clone', url, path]
            subprocess.check_call(cmd, cwd=path)
            return True
        except subprocess.CalledProcessError as e:
          cmd_str = ' '.join(cmd)
          self.log.error("git clone command \"{0}\" failed: {1}".format(cmd_str, e.output))
          return False

    def _update_repo(self, path, force=False, commit=None):
        """Updates a repository to a particular version, or the latest version if commit is None."""

        if not self._is_repo(path):
            return False
        try:
            subprocess.check_call(['git', 'fetch'])
            cmd = ['git', 'checkout']

            if force:
                cmd.append('--force')
            if commit:
                cmd.append(commit)

            subprocess.check_call(cmd)
            return True
        except:
            return False

    def _parse_repo_url(self, path):
        """Parses a string, attempting to find a folder.git extension at the end."""
        url_re = re.compile(r'.*\/(?P<dir>[^\/\.]*).git\/*')
        match = url_re.search(path)
        if match is not None:
            return match.group('dir')
        return None

    @botcmd
    def paper_add(self, mess, args):
        """Adds a paper to the repository of papers."""
        self._check_requirements()

        folder = self._parse_repo_url(args)

        if folder is None:
            return "Cannot parse URL for repository folder name."

        papers_dir = os.path.join(self.config['SCRIPTORIUM_LOCATION'], 'papers')
        paper_dir = os.path.join(papers_dir, folder)

        if os.path.exists(paper_dir):
            return "{0} already exists in the papers folder, refusing to overwrite.".format(folder)

        if self._clone_repo(args, papers_dir):
            return "Downloaded paper repository {0}".format(folder)
        else:
            return "Could not download specified paper repository."

    @botcmd
    def paper_update(self, mess, args):
        """Updates a paper to the specified version."""
        self._check_requirements()

        template_dir = os.path.join(self.config["SCRIPTORIUM_LOCATION"], 'papers', args)
        if not self._is_repo(template_dir):
            return "{0} is not a valid paper.".format(args)
        if self._update_repo(template_dir):
            return "{0} has been updated to the latest version.".format(args)

    @botcmd
    def paper_make(self, mess, args):
        """Attempts to make a paper, and returns the PDF if successful."""
        pass

    @botcmd
    def template_add(self, mess, args):
        """Command to add a template to the Scriptorium setup."""
        self._check_requirements()

        folder = self._parse_repo_url(args)

        if folder is None:
          return "Cannot parse URL for repository folder name."

        templates_dir = os.path.join(self.config['SCRIPTORIUM_LOCATION'], 'templates')
        template_path = os.path.join(templates_dir, folder)
        if os.path.exists(template_path):
            return "Refusing to overwrite template {0}".format(folder)

        if self._clone_repo(args, templates_dir):
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
        if self._update_repo(template_dir):
            return "{0} has been updated to the latest version.".format(args)


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
