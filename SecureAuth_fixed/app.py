from flask import Flask
from database import init_db
from routes.auth import auth_bp
from routes.protected import protected_bp

app = Flask(__name__)
app.secret_key = "supersecretkey_change_in_production"

# Register blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(protected_bp)

# Initialize database on startup
with app.app_context():
    init_db()

if __name__ == '__main__':
    app.run(debug=True)
