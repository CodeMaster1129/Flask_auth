from api.config import app
import api.auth

if __name__ == "__main__":
  app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)
