from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from models import db
from routes import bp as main_bp
from services import nvd_service

app = Flask(__name__)
app.config.from_object('config.Config')

# Initialize extensions
db.init_app(app)
migrate = Migrate(app, db)

# Initialize services
nvd_service.init_app(app)

# Register blueprints
app.register_blueprint(main_bp)

if __name__ == '__main__':
    app.run(debug=True) 