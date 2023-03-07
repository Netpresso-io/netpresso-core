from flask import Flask, request, send_file
import os

app = Flask(__name__)

@app.route('/download')
def download():
    # Open the file to be served
    file_path = 'file.bin'

    # Set up the file to upload and download
    file_size = 1024 * 1024 * 100  # 1 MB
    file_data = os.urandom(file_size)

    # Serve the file for download
    return send_file(file_data, as_attachment=True, download_name='download.bin')

@app.route('/upload', methods=['PUT'])
def upload():
    file = request.data
    file_size = len(file)

    return 'good', 200

if __name__ == '__main__':
    # Set up the server address and port
    server_address = ('localhost', 5000)

    # Start the server
    app.run(host=server_address[0], port=server_address[1], debug=False)
