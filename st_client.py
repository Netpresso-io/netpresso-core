import urllib.request
import os
import time

def measure_upload(url):
    # Set up the file to upload and download
    file_size = 1024 * 1024 * 1 # 1 MB
    file_data = os.urandom(file_size)

    # Measure upload bandwidth
    start_time = time.time()
    req = urllib.request.Request(url, data=file_data, method='PUT')
    with urllib.request.urlopen(req) as f:
        response = f.read()
    end_time = time.time()
    upload_speed = file_size / (end_time - start_time) / 1024 / 1024 # Mbps

    # Return the results
    return upload_speed

def measure_download(url):
    file_size = 1024 * 1024  # 1 MB
    file_data = os.urandom(file_size)

    # Measure download bandwidth
    start_time = time.time()
    urllib.request.urlretrieve(url, 'download.bin')
    end_time = time.time()
    download_speed = file_size / (end_time - start_time) / 1024 / 1024  # Mbps

    # Delete the temporary files
    os.remove('download.bin')

    # Return the results
    return download_speed

if __name__ == '__main__':
    url_download = 'http://localhost:5000/download'
    url_upload = 'http://localhost:5000/upload'
    upload_speed = measure_upload(url_upload)
    download_speed = measure_download(url_download)
    print(f'Download speed: {download_speed:.2f} Mbps')
    print(f'Upload speed: {upload_speed:.2f} Mbps')
