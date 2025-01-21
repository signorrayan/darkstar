from flask import Flask, request, jsonify
import subprocess
import xml.etree.ElementTree as ET
import requests

app = Flask(__name__)

#? Create target
@app.route('/create_target', methods=['POST'])
def create_target():
    data = request.get_json()
    command = data['command']
    print(command)
    
    #? Create target
    targetID = subprocess.getoutput(command)
    
    if 'Error' in targetID:
        return jsonify({'message': 'Failed to create target'})
    else:
        root = ET.fromstring(targetID)
        targetID = root.attrib['id']
        return jsonify({'message': targetID})


#? Create task
@app.route('/create_task', methods=['POST'])
def create_task():
    data = request.get_json()
    command = data['command']
    print(command)
    
    #? Create task
    taskID = subprocess.getoutput(command)
    
    if 'Error' in taskID:
        return jsonify({'message': 'Failed to create task'})
    else:
        root = ET.fromstring(taskID)
        taskID = root.attrib['id']
        return jsonify({'message': f"{taskID}"})


#? run_task
@app.route('/run_task', methods=['POST'])
def run_task():
    data = request.get_json()
    command = data['command']
    print(command)
    
    #? Run task
    reportID = subprocess.getoutput(command)
    
    if 'Error' in reportID:
        return jsonify({'message': 'Failed to run task'})
    else:
        reportID = reportID.split(">")[2].split("<")[0]
        return jsonify({'message': command})



#? check_if_finished
@app.route('/check_if_finished', methods=['POST'])
def check_if_finished():
    data = request.get_json()
    command = data['command']
    print(command)
    
    #? Check if finished
    status = subprocess.getoutput(command)
    
    return jsonify({'message': status})


#? wait_for_scan
@app.route('/wait_for_scan', methods=['POST'])
def wait_for_scan():
    data = request.get_json()
    command = data['command']
    print(command)
    
    #? Wait for scan
    status = subprocess.getoutput(command)
    
    return jsonify({'message': status})

#? get report
@app.route('/get_report')
def get_report():
    data = requests.json()
    command = data['command']

    report_data = subprocess.getoutput(command)

    return jsonify({'message': report_data})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)


