"""Tests for choosing the Sagemcom API mode and HTTP session per router."""

from unittest.mock import AsyncMock, Mock, patch

from homeassistant import config_entries
from homeassistant.config_entries import ConfigEntryState
from homeassistant.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_SSL,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
)
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.helpers.aiohttp_client import async_get_clientsession
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry
from sagemcom_api.client import SagemcomClient
from sagemcom_api.enums import ApiMode, EncryptionMethod
from sagemcom_api.exceptions import AuthenticationException
from sagemcom_api.models import DeviceInfo

from custom_components.sagemcom_fast.api import _prepare_client
from custom_components.sagemcom_fast.config_flow import async_detect_encryption_method
from custom_components.sagemcom_fast.const import CONF_ENCRYPTION_METHOD, DOMAIN

USER_INPUT = {
    CONF_HOST: "192.0.2.1",
    CONF_USERNAME: "admin",
    CONF_PASSWORD: "secret",
    CONF_SSL: False,
    CONF_VERIFY_SSL: False,
}


async def _async_setup(
    hass: HomeAssistant,
    config_entry: MockConfigEntry,
    sagemcom_client: Mock,
    gateway: DeviceInfo,
) -> Mock:
    sagemcom_client.get_device_info.return_value = gateway
    sagemcom_client.get_hosts.return_value = []
    config_entry.add_to_hass(hass)
    with patch(
        "custom_components.sagemcom_fast.api.SagemcomClient",
        return_value=sagemcom_client,
    ) as client_class:
        assert await hass.config_entries.async_setup(config_entry.entry_id)
        await hass.async_block_till_done()
    assert config_entry.state is ConfigEntryState.LOADED
    return client_class


async def test_legacy_router_is_pinned_to_legacy_api(
    hass: HomeAssistant,
    enable_custom_integrations: None,
    config_entry: MockConfigEntry,
    sagemcom_client: Mock,
    gateway: DeviceInfo,
) -> None:
    """Existing routers must not fall back to REST on a transient error page."""
    client_class = await _async_setup(hass, config_entry, sagemcom_client, gateway)

    kwargs = client_class.call_args.kwargs
    assert kwargs["api_mode"] is ApiMode.LEGACY
    assert kwargs["authentication_method"] is EncryptionMethod.MD5
    assert kwargs["session"] is async_get_clientsession(hass, verify_ssl=True)


async def test_rest_router_gets_own_session_closed_on_unload(
    hass: HomeAssistant,
    enable_custom_integrations: None,
    config_entry: MockConfigEntry,
    sagemcom_client: Mock,
    gateway: DeviceInfo,
) -> None:
    """REST routers need a cookie jar that accepts cookies from IP hosts."""
    config_entry = MockConfigEntry(
        domain=DOMAIN,
        data={**config_entry.data, CONF_ENCRYPTION_METHOD: EncryptionMethod.NONE},
        options=config_entry.options,
    )
    client_class = await _async_setup(hass, config_entry, sagemcom_client, gateway)

    kwargs = client_class.call_args.kwargs
    session = kwargs["session"]
    assert kwargs["api_mode"] is ApiMode.REST
    assert session is not async_get_clientsession(hass, verify_ssl=True)
    assert session.cookie_jar._unsafe  # pylint: disable=protected-access

    assert await hass.config_entries.async_unload(config_entry.entry_id)
    assert session.closed


async def _async_submit_user_step(
    hass: HomeAssistant, detection_client: Mock, validation_client: Mock
):
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": config_entries.SOURCE_USER}
    )
    with (
        patch(
            "custom_components.sagemcom_fast.config_flow.SagemcomClient",
            return_value=detection_client,
        ),
        patch(
            "custom_components.sagemcom_fast.api.SagemcomClient",
            return_value=validation_client,
        ) as validation_class,
        patch("custom_components.sagemcom_fast.async_setup_entry", return_value=True),
    ):
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"], USER_INPUT
        )
    return result, validation_class


@pytest.mark.parametrize(
    ("detected", "api_mode"),
    [(EncryptionMethod.SHA512, ApiMode.LEGACY), (EncryptionMethod.NONE, ApiMode.REST)],
)
async def test_config_flow_validates_with_entry_client_setup(
    hass: HomeAssistant,
    enable_custom_integrations: None,
    sagemcom_client: Mock,
    detected: EncryptionMethod,
    api_mode: ApiMode,
) -> None:
    """Credentials must be validated the same way the config entry connects."""
    detection_client = Mock(spec=SagemcomClient)
    detection_client.get_encryption_method.return_value = detected

    result, validation_class = await _async_submit_user_step(
        hass, detection_client, sagemcom_client
    )

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"][CONF_ENCRYPTION_METHOD] == detected
    kwargs = validation_class.call_args.kwargs
    assert kwargs["api_mode"] is api_mode
    sagemcom_client.login.assert_awaited_once()
    sagemcom_client.logout.assert_awaited_once()
    if api_mode is ApiMode.REST:
        assert kwargs["session"].closed


async def test_config_flow_without_matching_method_is_invalid_auth(
    hass: HomeAssistant,
    enable_custom_integrations: None,
    sagemcom_client: Mock,
) -> None:
    """No accepted login method must be reported instead of storing None."""
    detection_client = Mock(spec=SagemcomClient)
    detection_client.get_encryption_method.return_value = None

    result, validation_class = await _async_submit_user_step(
        hass, detection_client, sagemcom_client
    )

    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "invalid_auth"}
    validation_class.assert_not_called()


async def test_detect_encryption_method_probes_sha512_first_and_logs_out() -> None:
    """SHA512 routers must not waste two failed MD5 logins or leak the probe session."""
    attempted_methods: list[tuple[EncryptionMethod | None, int]] = []
    client = SagemcomClient(
        host="192.0.2.1",
        username="admin",
        password="secret",
        session=Mock(),
    )

    async def fake_login() -> bool:
        attempted_methods.append((client.authentication_method, client._request_id))
        if client.authentication_method is not EncryptionMethod.SHA512:
            raise AuthenticationException("wrong method")
        return True

    client.login = fake_login  # type: ignore[method-assign]
    logout_mock = AsyncMock()
    client.logout = logout_mock  # type: ignore[method-assign]

    detected = await async_detect_encryption_method(client)

    assert detected is EncryptionMethod.SHA512
    assert attempted_methods == [(EncryptionMethod.SHA512, -1)]
    logout_mock.assert_awaited_once()


async def test_detect_encryption_method_resets_request_id_between_probes() -> None:
    """Each encryption probe must start at request_id -1 and close its session."""
    attempted_methods: list[tuple[EncryptionMethod | None, int]] = []
    client = SagemcomClient(
        host="192.0.2.1",
        username="admin",
        password="secret",
        session=Mock(),
    )

    async def fake_login() -> bool:
        client._request_id += 1
        attempted_methods.append((client.authentication_method, client._request_id))
        if client.authentication_method is EncryptionMethod.SHA512:
            raise AuthenticationException("not sha512")
        return True

    client.login = fake_login  # type: ignore[method-assign]
    logout_mock = AsyncMock()
    client.logout = logout_mock  # type: ignore[method-assign]

    detected = await async_detect_encryption_method(client)

    assert detected is EncryptionMethod.MD5
    assert attempted_methods == [
        (EncryptionMethod.SHA512, 0),
        (EncryptionMethod.MD5, 0),
    ]
    logout_mock.assert_awaited_once()


async def test_prepared_client_resets_session_id_before_relogin() -> None:
    """A legacy client that logged out must not send session-id -1 on the next login."""
    observed_session_ids: list[int] = []
    client = SagemcomClient(
        host="192.0.2.1",
        username="admin",
        password="secret",
        authentication_method=EncryptionMethod.SHA512,
        session=Mock(),
        api_mode=ApiMode.LEGACY,
    )

    async def fake_login() -> bool:
        observed_session_ids.append(client._session_id)
        client._session_id = 12345
        return True

    client.login = fake_login  # type: ignore[method-assign]
    _prepare_client(client)

    await client.login()
    # sagemcom_api.logout() sets _session_id = -1 instead of 0
    client._session_id = -1
    await client.login()

    assert observed_session_ids == [0, 0]


