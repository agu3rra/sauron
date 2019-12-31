from flask import Flask, Response, request
import resources

# Setup application
app = Flask(__name__, instance_relative_config=True)
app.config.from_mapping(
    SECRET_KEY='DEV',
)

# Register Blueprints
app.register_blueprint(resources.status)
app.register_blueprint(resources.scan)

# Run main app: $ python app.py
app.run()
