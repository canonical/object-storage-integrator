#!/usr/bin/env python3
# Copyright 2024 Canonical Limited
# See LICENSE file for licensing details.

"""Object Storage manager."""

from utils.logging import WithLogging


class ObjectStorageManager(WithLogging):
    """Kyuubi manager class."""

    def __init__(self, relation_data):
        self.relation_data = relation_data


    def update(self, azure_connection_info):
        if len(self.relation_data.relations) > 0:
            for relation in self.relation_data.relations:
                self.relation_data.update_relation_data(relation.id, azure_connection_info.to_dict())
