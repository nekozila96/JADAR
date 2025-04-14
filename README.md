#Installing - sh install.sh
apt update -y 
apt install python3 -y
apt install python3-pip -y
apt install python3-venv -y
python3 -m venv myenv
pip install -r requirements.txt


## Usage
Step 0: source myenv/bin/activate
Step 1: git clone -b test_05 https://github.com/appsecco/dvja.git
Step 1: semgrep login then sign in according to the github/gitlab account
Step 2: python main.py
