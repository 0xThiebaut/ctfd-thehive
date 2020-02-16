#!/usr/bin/env python3
# encoding: utf-8
from urllib import parse

import requests
from cortexutils.responder import Responder

severities = {1: "low", 2: "medium", 3: "high"}


class CTFdTheHive(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.token = self.get_param(
            'config.token', None, 'Missing privileged CTFd access token')
        self.api = self.get_param(
            'config.api', 'https://localhost/api/v1/')
        self.action = self.get_param(
            'config.action', None, 'Missing action')
        self.low = self.get_param(
            'config.low', 10)
        self.medium = self.get_param(
            'config.medium', 25)
        self.high = self.get_param(
            'config.high', 100)
        self.name = self.get_param(
            'config.award.name', 'Enlightened')
        self.category = self.get_param(
            'config.award.category', 'Monitoring')
        self.icon = self.get_param(
            'config.award.icon')

    def run(self):
        Responder.run(self)

        # Get some values from the alert
        title = self.get_param('data.title', None, 'Missing title for alert')
        source = self.get_param('data.source', None, 'Missing source for alert')
        reference = self.get_param('data.sourceRef', None, 'Missing type for alert')
        severity = self.get_param('data.severity', None, 'Missing type for alert')

        # Interpret the CTFd user identifier
        try:
            user = int(source)
        except ValueError:
            self.error(f'The source "{source}" does not seem like a valid CTFd user identifier')
            user = -1

        # Compute the reward...
        if severity == 3:
            value = self.high
        elif severity == 2:
            value = self.medium
        else:
            value = self.low

        # ...and make it negative if we penalize
        if self.action == "penalize":
            value = -value
            state = "incorrectly"
        else:
            state = "successfully"

        # Generate the reward
        desc = f'The "{title}" alert {state} detected a {severities[severity]} severity event (#{reference}).'
        award = {
            'user_id': user,
            'name': self.name,
            'description': desc,
            'category': self.category,
            'icon': self.icon,
            'value': value
        }

        # Send the reward
        endpoint = parse.urljoin(self.api, 'awards')
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization': f'Bearer {self.token}'
        }
        r = requests.post(endpoint, json=award, headers=headers)

        # Interpret the response
        if r.ok:
            self.report({'award': award, 'response': r.text})
        else:
            self.error(f'An error occurred while contacting CTFd at {endpoint} ({r.status_code} {r.reason}): {r.text}')

    def operations(self, raw):
        return [self.build_operation('MarkAlertAsRead')]


if __name__ == "__main__":
    CTFdTheHive().run()
