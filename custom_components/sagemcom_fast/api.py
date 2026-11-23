"""Create Sagemcom F@st API clients."""

from __future__ import annotations

from aiohttp import ClientSession, CookieJar
from homeassistant.core import HomeAssistant
from homeassistant.helpers import aiohttp_client
from sagemcom_api.client import SagemcomClient
from sagemcom_api.enums import ApiMode, EncryptionMethod
from sagemcom_api.exceptions import InvalidSessionException


def _prepare_client(client: SagemcomClient) -> SagemcomClient:
    """Ensure legacy login resets session state and empty replies raise InvalidSessionException."""
    if type(client) is not SagemcomClient:
        return client

    original_login = client.login
    original_get_device_info = client.get_device_info
    original_get_hosts = client.get_hosts

    async def login():
        if client.api_mode != ApiMode.REST:
            client._session_id = 0  # pylint: disable=protected-access
            client._server_nonce = ""  # pylint: disable=protected-access
            client._request_id = -1  # pylint: disable=protected-access
        return await original_login()

    async def get_device_info():
        try:
            return await original_get_device_info()
        except TypeError as exception:
            raise InvalidSessionException(
                "Empty DeviceInfo response from gateway"
            ) from exception

    async def get_hosts(*args, **kwargs):
        try:
            return await original_get_hosts(*args, **kwargs)
        except TypeError as exception:
            raise InvalidSessionException(
                "Empty Hosts response from gateway"
            ) from exception

    client.login = login  # type: ignore[method-assign]
    client.get_device_info = get_device_info  # type: ignore[method-assign]
    client.get_hosts = get_hosts  # type: ignore[method-assign]
    return client


def create_client(
    hass: HomeAssistant,
    *,
    host: str,
    username: str,
    password: str,
    encryption_method: EncryptionMethod,
    ssl: bool,
    verify_ssl: bool,
) -> tuple[SagemcomClient, ClientSession | None]:
    """Return a client and the session the caller must detach, if it owns one."""
    if encryption_method is EncryptionMethod.NONE:
        # REST firmware keeps its session in a cookie set by an IP address,
        # which the shared Home Assistant cookie jar rejects. Legacy routers
        # must keep the shared jar: an unsafe jar breaks some of them.
        session = aiohttp_client.async_create_clientsession(
            hass,
            verify_ssl=verify_ssl,
            auto_cleanup=False,
            cookie_jar=CookieJar(unsafe=True),
        )
        owned_session: ClientSession | None = session
        api_mode = ApiMode.REST
    else:
        session = aiohttp_client.async_get_clientsession(hass, verify_ssl=verify_ssl)
        owned_session = None
        # Without a pin, a transient error page makes the client fall back to
        # REST, whose calls then fail with an auth error and trigger reauth.
        api_mode = ApiMode.LEGACY

    client = SagemcomClient(
        host=host,
        username=username,
        password=password,
        authentication_method=encryption_method,
        session=session,
        ssl=ssl,
        api_mode=api_mode,
    )
    return _prepare_client(client), owned_session
