from flask import Flask
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # 解决跨域问题

# 测试路由
@app.route('/')
def home():
    return {"message": "后端部署成功！", "status": "ok"}

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)  # 必须加 host 和 port！