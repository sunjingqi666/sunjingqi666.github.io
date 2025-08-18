from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import jwt
import datetime
from functools import wraps
from sqlalchemy import or_

# 初始化Flask应用
app = Flask(__name__)

# 配置（生产环境需修改SECRET_KEY为环境变量）
app.config['SECRET_KEY'] = 'dev-secret-key-2025'  # 开发用密钥
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///campus.db'  # SQLite数据库
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 初始化数据库
db = SQLAlchemy(app)


# ------------------------------
# 数据模型定义
# ------------------------------

# 1. 用户模型
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True, nullable=False)  # 唯一标识
    account = db.Column(db.String(50), unique=True, nullable=False)    # 账号（不可改）
    password = db.Column(db.String(100), nullable=False)               # 密码哈希
    nickname = db.Column(db.String(50), nullable=False)                # 昵称（可改）
    class_name = db.Column(db.String(50))                              # 班级/部门
    is_admin = db.Column(db.Boolean, default=False)                    # 管理员权限
    is_super = db.Column(db.Boolean, default=False)                    # 超级管理员权限
    is_banned = db.Column(db.Boolean, default=False)                   # 账号状态
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)


# 2. 公告模型
class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)                  # 标题
    content = db.Column(db.Text, nullable=False)                       # 内容
    category = db.Column(db.String(50), default="未分类")              # 分类
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)  # 发布时间
    updated_at = db.Column(db.DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)  # 更新时间
    author_id = db.Column(db.String(50), db.ForeignKey('user.public_id'), nullable=False)  # 发布人
    is_active = db.Column(db.Boolean, default=True)                    # 是否有效


# 3. 好友关系模型（双向存储，A是B的好友则B也是A的好友）
class Friend(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(50), db.ForeignKey('user.public_id'), nullable=False)  # 用户
    friend_id = db.Column(db.String(50), db.ForeignKey('user.public_id'), nullable=False)  # 好友
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)  # 添加时间
    # 确保一对好友只存一条记录（通过联合唯一约束）
    __table_args__ = (db.UniqueConstraint('user_id', 'friend_id', name='unique_friend'),)


# 4. 聊天消息模型（每对好友只保留最近10条）
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.String(50), db.ForeignKey('user.public_id'), nullable=False)  # 发送者
    receiver_id = db.Column(db.String(50), db.ForeignKey('user.public_id'), nullable=False)  # 接收者
    content = db.Column(db.Text, nullable=False)  # 消息内容
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)  # 发送时间


# 5. 网站建议模型
class Suggestion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(50), db.ForeignKey('user.public_id'), nullable=False)  # 提交人
    content = db.Column(db.Text, nullable=False)  # 建议内容
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)  # 提交时间
    is_read = db.Column(db.Boolean, default=False)  # 是否已读


# ------------------------------
# 通用工具函数
# ------------------------------

# 登录验证装饰器（所有需要登录的接口都需要添加）
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        
        if not token:
            return jsonify({'message': '请先登录获取令牌！'}), 401
        
        try:
            # 解码Token（验证有效性和过期时间）
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': '令牌无效或已过期！'}), 401
        
        # 检查账号是否被禁用
        if current_user.is_banned:
            return jsonify({'message': '账号已被禁用，请联系管理员！'}), 403
        
        return f(current_user, *args, **kwargs)
    return decorated


# 管理员权限验证（仅管理员可用的接口）
def admin_required(f):
    @wraps(f)
    @token_required
    def decorated(current_user, *args, **kwargs):
        if not current_user.is_admin:
            return jsonify({'message': '没有管理员权限！'}), 403
        return f(current_user, *args, **kwargs)
    return decorated


# 超级管理员权限验证（仅超级管理员可用的接口）
def super_admin_required(f):
    @wraps(f)
    @token_required
    def decorated(current_user, *args, **kwargs):
        if not current_user.is_super:
            return jsonify({'message': '没有超级管理员权限！'}), 403
        return f(current_user, *args, **kwargs)
    return decorated


# ------------------------------
# 用户相关接口
# ------------------------------

# 1. 用户注册
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    
    # 校验必填字段
    if not all(k in data for k in ['account', 'password', 'nickname']):
        return jsonify({'message': '账号、密码和昵称不能为空！'}), 400
    
    # 检查账号是否已存在
    if User.query.filter_by(account=data['account']).first():
        return jsonify({'message': '该账号已被注册！'}), 400
    
    # 创建新用户（密码哈希存储）
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(
        public_id=str(uuid.uuid4()),
        account=data['account'],
        password=hashed_password,
        nickname=data['nickname'],
        class_name=data.get('class_name', '')
    )
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({'message': '注册成功，请登录！'}), 201


# 2. 用户登录
@app.route('/login', methods=['POST'])
def login():
    auth = request.get_json()
    
    # 校验输入
    if not auth or not auth.get('account') or not auth.get('password'):
        return jsonify({'message': '请提供账号和密码！'}), 400
    
    # 查找用户
    user = User.query.filter_by(account=auth['account']).first()
    if not user:
        return jsonify({'message': '账号不存在！'}), 401
    
    # 检查账号状态
    if user.is_banned:
        return jsonify({'message': '账号已被禁用！'}), 403
    
    # 验证密码
    if check_password_hash(user.password, auth['password']):
        # 生成24小时有效的Token
        token = jwt.encode({
            'public_id': user.public_id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        
        return jsonify({
            'token': token,
            'user': {
                'public_id': user.public_id,
                'account': user.account,
                'nickname': user.nickname,
                'is_admin': user.is_admin,
                'is_super': user.is_super
            }
        })
    
    return jsonify({'message': '密码错误！'}), 401


# 3. 修改用户昵称（仅本人）
@app.route('/user/nickname', methods=['PUT'])
@token_required
def update_nickname(current_user):
    data = request.get_json()
    if not data.get('nickname'):
        return jsonify({'message': '昵称不能为空！'}), 400
    
    current_user.nickname = data['nickname']
    db.session.commit()
    return jsonify({'message': '昵称修改成功！', 'nickname': current_user.nickname})


# 4. 修改密码（需原密码+两次新密码一致）
@app.route('/user/password', methods=['PUT'])
@token_required
def update_password(current_user):
    data = request.get_json()
    
    # 校验输入
    if not all(k in data for k in ['old_password', 'new_password', 'confirm_password']):
        return jsonify({'message': '请提供原密码、新密码和确认密码！'}), 400
    
    # 验证原密码
    if not check_password_hash(current_user.password, data['old_password']):
        return jsonify({'message': '原密码错误！'}), 401
    
    # 验证两次新密码一致
    if data['new_password'] != data['confirm_password']:
        return jsonify({'message': '两次输入的新密码不一致！'}), 400
    
    # 更新密码
    current_user.password = generate_password_hash(data['new_password'], method='sha256')
    db.session.commit()
    return jsonify({'message': '密码修改成功，请重新登录！'})


# 5. 获取当前用户信息
@app.route('/user/me', methods=['GET'])
@token_required
def get_current_user(current_user):
    return jsonify({
        'public_id': current_user.public_id,
        'account': current_user.account,
        'nickname': current_user.nickname,
        'class_name': current_user.class_name,
        'is_admin': current_user.is_admin,
        'is_super': current_user.is_super,
        'created_at': current_user.created_at.strftime('%Y-%m-%d %H:%M')
    })


# ------------------------------
# 公告相关接口
# ------------------------------

# 1. 发布公告（仅管理员）
@app.route('/announcements', methods=['POST'])
@admin_required
def create_announcement(current_user):
    data = request.get_json()
    
    # 校验必填字段
    if not data.get('title') or not data.get('content'):
        return jsonify({'message': '标题和内容不能为空！'}), 400
    
    # 创建公告
    new_ann = Announcement(
        title=data['title'],
        content=data['content'],
        category=data.get('category', '未分类'),
        author_id=current_user.public_id
    )
    db.session.add(new_ann)
    db.session.commit()
    
    return jsonify({
        'message': '公告发布成功！',
        'announcement': {
            'id': new_ann.id,
            'title': new_ann.title,
            'created_at': new_ann.created_at.strftime('%Y-%m-%d %H:%M')
        }
    }), 201


# 2. 获取公告列表（支持分页和分类筛选）
@app.route('/announcements', methods=['GET'])
def get_announcements():
    # 分页参数（默认第1页，每页10条）
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    # 分类筛选
    category = request.args.get('category')
    query = Announcement.query.filter_by(is_active=True)  # 只显示有效公告
    
    if category:
        query = query.filter_by(category=category)
    
    # 按发布时间倒序（最新在前）
    pagination = query.order_by(Announcement.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    announcements = pagination.items
    
    # 格式化返回
    result = []
    for ann in announcements:
        author = User.query.filter_by(public_id=ann.author_id).first()
        result.append({
            'id': ann.id,
            'title': ann.title,
            'category': ann.category,
            'created_at': ann.created_at.strftime('%Y-%m-%d %H:%M'),
            'author': author.nickname if author else '未知'
        })
    
    return jsonify({
        'announcements': result,
        'pagination': {
            'total': pagination.total,
            'pages': pagination.pages,
            'current_page': page,
            'per_page': per_page
        }
    })


# 3. 获取公告详情
@app.route('/announcements/<int:ann_id>', methods=['GET'])
def get_announcement_detail(ann_id):
    ann = Announcement.query.get_or_404(ann_id)
    author = User.query.filter_by(public_id=ann.author_id).first()
    
    return jsonify({
        'id': ann.id,
        'title': ann.title,
        'content': ann.content,
        'category': ann.category,
        'created_at': ann.created_at.strftime('%Y-%m-%d %H:%M'),
        'updated_at': ann.updated_at.strftime('%Y-%m-%d %H:%M'),
        'author': author.nickname if author else '未知',
        'is_active': ann.is_active
    })


# 4. 修改公告（仅发布者或超级管理员）
@app.route('/announcements/<int:ann_id>', methods=['PUT'])
@admin_required
def update_announcement(current_user, ann_id):
    ann = Announcement.query.get_or_404(ann_id)
    
    # 权限校验：发布者或超级管理员
    if not (current_user.public_id == ann.author_id or current_user.is_super):
        return jsonify({'message': '没有权限修改此公告！'}), 403
    
    data = request.get_json()
    # 更新字段（只更新传入的非空值）
    if data.get('title'):
        ann.title = data['title']
    if data.get('content'):
        ann.content = data['content']
    if 'category' in data:
        ann.category = data['category']
    if 'is_active' in data:
        ann.is_active = data['is_active']
    
    db.session.commit()
    return jsonify({'message': '公告更新成功！'})


# 5. 删除公告（仅发布者或超级管理员）
@app.route('/announcements/<int:ann_id>', methods=['DELETE'])
@admin_required
def delete_announcement(current_user, ann_id):
    ann = Announcement.query.get_or_404(ann_id)
    
    # 权限校验：发布者或超级管理员
    if not (current_user.public_id == ann.author_id or current_user.is_super):
        return jsonify({'message': '没有权限删除此公告！'}), 403
    
    db.session.delete(ann)
    db.session.commit()
    return jsonify({'message': '公告已删除！'})


# ------------------------------
# 搜索功能（搜索公告）
# ------------------------------
@app.route('/search/announcements', methods=['GET'])
def search_announcements():
    keyword = request.args.get('keyword', '')
    if not keyword:
        return jsonify({'message': '请输入搜索关键词！'}), 400
    
    # 按标题或内容模糊搜索（只搜有效公告）
    results = Announcement.query.filter(
        Announcement.is_active == True,
        or_(
            Announcement.title.like(f'%{keyword}%'),
            Announcement.content.like(f'%{keyword}%')
        )
    ).order_by(Announcement.created_at.desc()).all()
    
    # 格式化返回
    announcements = []
    for ann in results:
        author = User.query.filter_by(public_id=ann.author_id).first()
        announcements.append({
            'id': ann.id,
            'title': ann.title,
            'content': ann.content[:100] + '...' if len(ann.content) > 100 else ann.content,  # 内容预览
            'category': ann.category,
            'created_at': ann.created_at.strftime('%Y-%m-%d %H:%M'),
            'author': author.nickname if author else '未知'
        })
    
    return jsonify({
        'count': len(announcements),
        'announcements': announcements
    })


# ------------------------------
# 好友系统接口
# ------------------------------

# 1. 通过账号搜索用户（用于添加好友）
@app.route('/search/users', methods=['GET'])
@token_required
def search_users(current_user):
    account = request.args.get('account', '')
    if not account:
        return jsonify({'message': '请输入账号关键词！'}), 400
    
    # 排除自己，按账号模糊搜索
    users = User.query.filter(
        User.public_id != current_user.public_id,
        User.account.like(f'%{account}%'),
        User.is_banned == False
    ).all()
    
    # 格式化返回（隐藏敏感信息）
    results = []
    for user in users:
        # 检查是否已是好友
        is_friend = Friend.query.filter_by(
            user_id=current_user.public_id,
            friend_id=user.public_id
        ).first() is not None
        
        results.append({
            'public_id': user.public_id,
            'account': user.account,
            'nickname': user.nickname,
            'class_name': user.class_name,
            'is_friend': is_friend
        })
    
    return jsonify({'count': len(results), 'users': results})


# 2. 添加好友（通过public_id）
@app.route('/friends', methods=['POST'])
@token_required
def add_friend(current_user):
    data = request.get_json()
    friend_public_id = data.get('friend_public_id')
    
    if not friend_public_id:
        return jsonify({'message': '请指定好友ID！'}), 400
    
    # 不能添加自己
    if friend_public_id == current_user.public_id:
        return jsonify({'message': '不能添加自己为好友！'}), 400
    
    # 检查好友是否存在且未被禁用
    friend = User.query.filter_by(
        public_id=friend_public_id,
        is_banned=False
    ).first()
    if not friend:
        return jsonify({'message': '该用户不存在或已被禁用！'}), 404
    
    # 检查是否已是好友
    if Friend.query.filter_by(
        user_id=current_user.public_id,
        friend_id=friend_public_id
    ).first():
        return jsonify({'message': '你们已经是好友了！'}), 400
    
    # 双向添加好友关系（A的好友列表有B，B的好友列表有A）
    new_friend1 = Friend(
        user_id=current_user.public_id,
        friend_id=friend_public_id
    )
    new_friend2 = Friend(
        user_id=friend_public_id,
        friend_id=current_user.public_id
    )
    db.session.add(new_friend1)
    db.session.add(new_friend2)
    db.session.commit()
    
    return jsonify({
        'message': f'已成功添加 {friend.nickname} 为好友！',
        'friend': {
            'public_id': friend.public_id,
            'account': friend.account,
            'nickname': friend.nickname
        }
    }), 201


# 3. 获取好友列表
@app.route('/friends', methods=['GET'])
@token_required
def get_friends(current_user):
    # 查询当前用户的所有好友
    friend_relations = Friend.query.filter_by(user_id=current_user.public_id).all()
    friend_ids = [rel.friend_id for rel in friend_relations]
    
    # 获取好友详细信息
    friends = []
    for fid in friend_ids:
        user = User.query.filter_by(public_id=fid).first()
        if user:
            friends.append({
                'public_id': user.public_id,
                'account': user.account,
                'nickname': user.nickname,
                'class_name': user.class_name,
                'added_at': next(rel.created_at for rel in friend_relations if rel.friend_id == fid).strftime('%Y-%m-%d')
            })
    
    # 按添加时间倒序（最新添加的在前）
    friends.sort(key=lambda x: x['added_at'], reverse=True)
    return jsonify({'count': len(friends), 'friends': friends})


# 4. 删除好友
@app.route('/friends/<string:friend_public_id>', methods=['DELETE'])
@token_required
def delete_friend(current_user, friend_public_id):
    # 双向删除好友关系
    rel1 = Friend.query.filter_by(
        user_id=current_user.public_id,
        friend_id=friend_public_id
    ).first()
    rel2 = Friend.query.filter_by(
        user_id=friend_public_id,
        friend_id=current_user.public_id
    ).first()
    
    if not rel1 or not rel2:
        return jsonify({'message': '你们不是好友！'}), 404
    
    db.session.delete(rel1)
    db.session.delete(rel2)
    db.session.commit()
    
    return jsonify({'message': '已成功删除好友！'})


# ------------------------------
# 聊天功能接口（仅好友间）
# ------------------------------

# 1. 发送消息（仅好友）
@app.route('/messages', methods=['POST'])
@token_required
def send_message(current_user):
    data = request.get_json()
    receiver_id = data.get('receiver_id')
    content = data.get('content')
    
    # 校验输入
    if not receiver_id or not content:
        return jsonify({'message': '请指定接收者和消息内容！'}), 400
    
    # 检查接收者是否存在
    receiver = User.query.filter_by(public_id=receiver_id).first()
    if not receiver or receiver.is_banned:
        return jsonify({'message': '接收者不存在或已被禁用！'}), 404
    
    # 检查是否为好友
    is_friend = Friend.query.filter_by(
        user_id=current_user.public_id,
        friend_id=receiver_id
    ).first() is not None
    if not is_friend:
        return jsonify({'message': '只能给好友发送消息！'}), 403
    
    # 发送消息
    new_msg = Message(
        sender_id=current_user.public_id,
        receiver_id=receiver_id,
        content=content
    )
    db.session.add(new_msg)
    
    # 只保留最近10条消息（双向清理）
    # 查询当前对话的所有消息
    conversation_msgs = Message.query.filter(
        or_(
            (Message.sender_id == current_user.public_id) & (Message.receiver_id == receiver_id),
            (Message.sender_id == receiver_id) & (Message.receiver_id == current_user.public_id)
        )
    ).order_by(Message.created_at.asc()).all()
    
    # 如果超过10条，删除最早的
    if len(conversation_msgs) > 10:
        for msg in conversation_msgs[:-10]:  # 保留最后10条
            db.session.delete(msg)
    
    db.session.commit()
    
    return jsonify({
        'message': '消息发送成功！',
        'msg_id': new_msg.id,
        'created_at': new_msg.created_at.strftime('%Y-%m-%d %H:%M:%S')
    }), 201


# 2. 获取与好友的聊天记录（最近10条）
@app.route('/messages/<string:friend_id>', methods=['GET'])
@token_required
def get_messages(current_user, friend_id):
    # 检查是否为好友
    is_friend = Friend.query.filter_by(
        user_id=current_user.public_id,
        friend_id=friend_id
    ).first() is not None
    if not is_friend:
        return jsonify({'message': '只能查看好友的聊天记录！'}), 403
    
    # 查询聊天记录（双向）
    messages = Message.query.filter(
        or_(
            (Message.sender_id == current_user.public_id) & (Message.receiver_id == friend_id),
            (Message.sender_id == friend_id) & (Message.receiver_id == current_user.public_id)
        )
    ).order_by(Message.created_at.asc()).all()  # 按时间正序（最早的在前）
    
    # 格式化返回
    result = []
    for msg in messages:
        sender = User.query.filter_by(public_id=msg.sender_id).first()
        result.append({
            'id': msg.id,
            'content': msg.content,
            'sender_id': msg.sender_id,
            'sender_nickname': sender.nickname if sender else '未知',
            'is_self': msg.sender_id == current_user.public_id,  # 是否是自己发送的
            'created_at': msg.created_at.strftime('%Y-%m-%d %H:%M:%S')
        })
    
    return jsonify({'count': len(result), 'messages': result})


# ------------------------------
# 网站建议接口
# ------------------------------

# 1. 提交网站建议（所有用户）
@app.route('/suggestions', methods=['POST'])
@token_required
def submit_suggestion(current_user):
    data = request.get_json()
    content = data.get('content')
    
    if not content:
        return jsonify({'message': '建议内容不能为空！'}), 400
    
    # 提交建议
    new_suggestion = Suggestion(
        user_id=current_user.public_id,
        content=content
    )
    db.session.add(new_suggestion)
    db.session.commit()
    
    return jsonify({'message': '感谢您的建议，我们会认真查看！'}), 201


# 2. 查看所有建议（仅超级管理员）
@app.route('/suggestions', methods=['GET'])
@super_admin_required
def get_suggestions(current_user):
    # 分页参数
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    # 查询建议（按提交时间倒序）
    pagination = Suggestion.query.order_by(Suggestion.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    suggestions = pagination.items
    
    # 格式化返回
    result = []
    for s in suggestions:
        user = User.query.filter_by(public_id=s.user_id).first()
        result.append({
            'id': s.id,
            'content': s.content,
            'user_account': user.account if user else '未知',
            'user_nickname': user.nickname if user else '未知',
            'created_at': s.created_at.strftime('%Y-%m-%d %H:%M'),
            'is_read': s.is_read
        })
    
    return jsonify({
        'suggestions': result,
        'pagination': {
            'total': pagination.total,
            'pages': pagination.pages,
            'current_page': page,
            'per_page': per_page
        }
    })


# 3. 标记建议为已读（仅超级管理员）
@app.route('/suggestions/<int:suggestion_id>/read', methods=['PUT'])
@super_admin_required
def mark_suggestion_read(current_user, suggestion_id):
    suggestion = Suggestion.query.get_or_404(suggestion_id)
    suggestion.is_read = True
    db.session.commit()
    return jsonify({'message': '已标记为已读！'})


# ------------------------------
# 初始化数据库（创建表和超级管理员）
# ------------------------------
def init_db():
    with app.app_context():
        db.create_all()  # 创建所有表
        
        # 创建默认超级管理员（如果不存在）
        if not User.query.filter_by(account='admin').first():
            hashed_password = generate_password_hash('admin1234', method='sha256')
            admin = User(
                public_id=str(uuid.uuid4()),
                account='admin',
                password=hashed_password,
                nickname='超级管理员',
                is_admin=True,
                is_super=True
            )
            db.session.add(admin)
            db.session.commit()
            print("初始化成功：默认超级管理员账号 'admin'，密码 'admin1234'")


# 启动服务
if __name__ == '__main__':
    init_db()  # 启动时初始化数据库
    app.run(debug=True)  # 开发模式运行，默认地址 http://127.0.0.1:5000
    
