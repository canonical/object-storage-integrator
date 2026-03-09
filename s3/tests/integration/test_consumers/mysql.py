import json
import logging
from jubilant import Juju
from tenacity import (
    retry,
    stop_after_attempt,
    wait_fixed,
)

logger = logging.getLogger(__name__)


@retry(stop=stop_after_attempt(30), wait=wait_fixed(5), reraise=True)
def get_mysql_cluster_status(juju: Juju, unit: str, cluster_set: bool = False) -> dict:
    """Get the cluster status by running the get-cluster-status action.

    Args:
        juju: The juju instance to use.
        unit: The unit on which to execute the action on
        cluster_set: Whether to get the cluster-set instead (optional)

    Returns:
        A dictionary representing the cluster status
    """
    task = juju.run(
        unit=unit,
        action="get-cluster-status",
        params={"cluster-set": cluster_set},
        wait=5 * 60,
    )

    status = task.results["status"]
    status = json.loads(status)
    return status


def get_mysql_primary_unit(juju: Juju, unit_name: str | None = None) -> str:
    """Get the current primary node of the cluster."""
    mysql_cluster_status = get_mysql_cluster_status(juju, unit_name)
    mysql_cluster_topology = mysql_cluster_status["defaultReplicaSet"]["topology"]

    for label, value in mysql_cluster_topology.items():
        if value["memberRole"] == "PRIMARY":
            return "/".join(label.rsplit("-", 1))

    raise Exception("No MySQL primary node found")
