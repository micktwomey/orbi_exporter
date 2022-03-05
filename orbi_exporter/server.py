import dataclasses
import logging
import re
from concurrent.futures import process

import fastapi
import fastapi.responses
import httpx
import pydantic
import structlog
import structlog.processors
import structlog.stdlib
from prometheus_client import make_asgi_app
from prometheus_client.core import REGISTRY, CounterMetricFamily, GaugeMetricFamily


class Config(pydantic.BaseSettings):
    orbi_ip: str
    orbi_username: str
    orbi_password: pydantic.SecretStr
    orbi_log_format: str = "console"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


app = fastapi.FastAPI()


def get_metric(orbi_name: str, value: str) -> CounterMetricFamily | GaugeMetricFamily:
    """Parses the orbi metric and emits the most appropriate prometheus metric"""
    for metric_type in ["txpkts", "rxpkts", "collisions", "txbs", "rxbs", "systime"]:
        regex = re.compile(rf"([a-z0-9]+)_{metric_type}")
        m = regex.match(orbi_name)
        if m is not None:
            interface = m.groups()[0]
            counter = CounterMetricFamily(
                name=metric_type,
                labels=["interface"],
                documentation=f"Network interface {interface} metric {metric_type} from {orbi_name}",
            )
            counter.add_metric(labels=[interface], value=int(value))
            return counter
    # Fallback to gauge
    return GaugeMetricFamily(
        name=orbi_name, documentation=f"Orbi metric {orbi_name}", value=int(value)
    )


@dataclasses.dataclass(frozen=True)
class OrbiCollector:
    ip: str
    username: str
    password: str

    def collect(self):
        log = structlog.stdlib.get_logger()
        url = f"http://{self.ip}/RST_statistic.htm"
        log.msg("Fetching Orbi stats", method="GET", url=url)
        log.debug("Authentication", username=self.username, password=self.password)
        response = httpx.get(url, auth=httpx.BasicAuth(self.username, self.password))
        log.msg(
            "Got response",
            method="GET",
            status_code=response.status_code,
            url=url,
            length=len(response.text),
        )
        s = response.text
        log.debug("Raw response", text=s)
        for name, value in re.findall(
            r'^var ([a-z0-9_]+)="([0-9]+)";$', s, re.MULTILINE
        ):
            log.msg("Scraped value", name=name, value=value)
            # yield GaugeMetricFamily(name, f"Orbi {name}", value=int(value))
            yield get_metric(orbi_name=name, value=value)
        # c = CounterMetricFamily("my_counter_total", "Help text", labels=["foo"])
        # c.add_metric(["bar"], 1.7)
        # c.add_metric(["baz"], 3.8)
        # yield c


@app.on_event("startup")
async def startup():
    config = Config()

    # Set up structlog
    processors = [
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.TimeStamper(fmt="iso"),
    ]
    if config.orbi_log_format == "json":
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.processors.ExceptionPrettyPrinter())
        processors.append(structlog.dev.ConsoleRenderer())
    structlog.configure(
        cache_logger_on_first_use=True,
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        processors=processors,
    )
    log = structlog.get_logger()
    log.info("Structlog configured", config=structlog.get_config())

    log.info("Config loaded", config=config)

    REGISTRY.register(
        OrbiCollector(
            ip=config.orbi_ip,
            username=config.orbi_username,
            password=config.orbi_password.get_secret_value(),
        )
    )
    log.info(
        "Orbi Collector configured",
        ip=config.orbi_ip,
        username=config.orbi_username,
        password=config.orbi_password,
    )


prometheus_app = make_asgi_app()
app.mount("/metrics", prometheus_app, name="metrics")


@app.get("/")
def root():
    return fastapi.responses.RedirectResponse("/metrics/")
