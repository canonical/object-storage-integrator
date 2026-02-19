"""Module containing utility functions."""

import json
import logging
from collections import namedtuple
from typing import Dict, List, Optional, Union

from ops import Application, Relation, RelationChangedEvent, Unit

logger = logging.getLogger(__name__)


Diff = namedtuple("Diff", "added changed deleted")
Diff.__doc__ = """
A tuple for storing the diff between two data mappings.

added - keys that were added
changed - keys that still exist but have new values
deleted - key that were deleted"""


def get_encoded_dict(
    relation: Relation, member: Union[Unit, Application], field: str
) -> Optional[Dict[str, str]]:
    """Retrieve and decode an encoded field from relation data."""
    data = json.loads(relation.data[member].get(field, "{}"))
    if isinstance(data, dict):
        return data
    logger.error("Unexpected datatype for %s instead of dict.", str(data))
    return None


def get_encoded_list(
    relation: Relation, member: Union[Unit, Application], field: str
) -> Optional[List[str]]:
    """Retrieve and decode an encoded field from relation data."""
    data = json.loads(relation.data[member].get(field, "[]"))
    if isinstance(data, list):
        return data
    logger.error("Unexpected datatype for %s instead of list.", str(data))
    return None


def set_encoded_field(
    relation: Relation,
    member: Union[Unit, Application],
    field: str,
    value: Union[str, list, Dict[str, str]],
) -> None:
    """Set an encoded field from relation data."""
    relation.data[member].update({field: json.dumps(value)})


def diff(event: RelationChangedEvent, bucket: Optional[Union[Unit, Application]]) -> Diff:
    """Retrieves the diff of the data in the relation changed databag.

    Args:
        event: relation changed event.
        bucket: bucket of the databag (app or unit)

    Returns:
        a Diff instance containing the added, deleted and changed
            keys from the event relation databag.
    """
    # Retrieve the old data from the data key in the application relation databag.
    if not bucket:
        return Diff([], [], [])

    old_data = get_encoded_dict(event.relation, bucket, "data")

    if not old_data:
        old_data = {}

    # Retrieve the new data from the event relation databag.
    new_data = (
        {key: value for key, value in event.relation.data[event.app].items() if key != "data"}
        if event.app
        else {}
    )

    # These are the keys that were added to the databag and triggered this event.
    added = new_data.keys() - old_data.keys()  # pyright: ignore [reportAssignmentType]
    # These are the keys that were removed from the databag and triggered this event.
    deleted = old_data.keys() - new_data.keys()  # pyright: ignore [reportAssignmentType]
    # These are the keys that already existed in the databag,
    # but had their values changed.
    changed = {
        key
        for key in old_data.keys() & new_data.keys()  # pyright: ignore [reportAssignmentType]
        if old_data[key] != new_data[key]  # pyright: ignore [reportAssignmentType]
    }
    # Convert the new_data to a serializable format and save it for a next diff check.
    set_encoded_field(event.relation, bucket, "data", new_data)

    # Return the diff with all possible changes.
    return Diff(added, changed, deleted)
