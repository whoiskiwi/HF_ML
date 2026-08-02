from flask import Flask, request
import os, zipfile, subprocess

app = Flask(__name__)
UPLOAD_DIR = "/tmp/datasets"

@app.route("/status", methods=["GET"])
def status():
    return "Worker is running", 200

@app.route("/upload", methods=["POST"])
def upload():
    if "dataset" not in request.files:
        return "Missing dataset file", 400

    f = request.files["dataset"]
    os.makedirs(UPLOAD_DIR, exist_ok=True)

    zip_path = os.path.join(UPLOAD_DIR, "upload.zip")
    f.save(zip_path)

    # Extract dataset
    dataset_dir = os.path.join(UPLOAD_DIR, "current")
    os.makedirs(dataset_dir, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as z:
        z.extractall(dataset_dir)

    print("[Worker] Dataset received and extracted.")

    # Vulnerability: executes loading_script.py from the dataset directly, with no sandbox or validation
    loader = os.path.join(dataset_dir, "loading_script.py")
    if os.path.exists(loader):
        print("[Worker] Found loading_script.py, executing...")
        subprocess.Popen(["python3", loader])

    return "Dataset processed successfully", 200

if __name__ == "__main__":
    print("[Worker] Dataset processing service started on port 8080")
    app.run(host="0.0.0.0", port=8080)
