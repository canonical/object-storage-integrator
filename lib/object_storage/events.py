"""Module that defines custom events for object storage relations."""

from ops import CharmEvents, EventSource, RelationEvent


class ObjectStorageEvent(RelationEvent):
    """Common event class for object storage related events."""

    pass


class StorageConnectionInfoRequestedEvent(ObjectStorageEvent):
    """The class representing an object storage connection info requested event."""

    pass


class StorageConnectionInfoChangedEvent(ObjectStorageEvent):
    """The class representing an object storage connection info changed event."""

    pass


class StorageConnectionInfoGoneEvent(ObjectStorageEvent):
    """The class representing an object storage connection info gone event."""

    pass


class StorageProviderEvents(CharmEvents):
    """Define events emitted by the provider side of a storage relation.

    These events are produced by a charm that provides storage connection
    information to requirers (an object-storage integrator). Providers
    should observe these and respond by publishing the current connection
    details per relation.

    Events:
        storage_connection_info_requested (StorageConnectionInfoRequestedEvent):
            Fired on the provider side to request/refresh storage connection info.
            Providers are expected to (re)publish all relevant relation data
            and secrets for the requesting relation.
    """

    storage_connection_info_requested = EventSource(StorageConnectionInfoRequestedEvent)


class StorageRequirerEvents(CharmEvents):
    """Define events emitted by the requirer side of a storage relation.

    These events are produced by a charm that consumes storage connection
    information. Requirers should react by updating their application config,
    restarting services, etc.

    Events:
        storage_connection_info_changed (StorageConnectionInfoChangedEvent):
            Fired on the requirer side when the provider publishes new or updated connection info.
            Handlers should read relation data/secrets and apply changes.

        storage_connection_info_gone (StorageConnectionInfoGoneEvent):
            Fired on the requirer side when previously available connection info has been removed or
            invalidated (e.g., relation departed, secret revoked). Handlers
            should gracefully degrade and update
            status accordingly.
    """

    storage_connection_info_changed = EventSource(StorageConnectionInfoChangedEvent)
    storage_connection_info_gone = EventSource(StorageConnectionInfoGoneEvent)
