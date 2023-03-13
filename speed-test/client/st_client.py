import speedtest
import time
import influxdb_client
from influxdb_client.client.write_api import SYNCHRONOUS

# TODO: switch to secret on beta release
INFLUX_URL = "http://influxdb:8086"
INFLUX_TOKEN = "admin-token"
INFLUX_ORG = "Netpresso"
INFLUX_BUCKET = "speed-test-metrics"

if __name__ == '__main__':
    client = influxdb_client.InfluxDBClient(
        url=INFLUX_URL,
        token=INFLUX_TOKEN,
        org=INFLUX_ORG
    )
    write_api = client.write_api(write_options=SYNCHRONOUS)
    st = speedtest.Speedtest()
    running = True
    while running:
        download_speed = round(st.download() / 1024 / 1024, 2)
        print(download_speed)
        p = influxdb_client.Point("speed-test").field("speed", download_speed)
        write_api.write(bucket=INFLUX_BUCKET, record=p)
        time.sleep(15)
