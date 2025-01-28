import pytest
from charm import AzureStorageIntegratorCharm
from interface_tester import InterfaceTester
from scenario.state import State


@pytest.fixture
def interface_tester(interface_tester: InterfaceTester):
    interface_tester.configure(
        charm_type=AzureStorageIntegratorCharm,
        state_template=State(
            leader=True,  # we need leadership
        ),
    )
    # this fixture needs to yield (NOT RETURN!) interface_tester again
    yield interface_tester
