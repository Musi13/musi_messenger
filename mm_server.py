from flask import Flask, request
import json

from flask_restplus import Api, Resource, abort

associations = {}

app = Flask(__name__)
api = Api(app, doc=False)

@api.route('/<key_hash>', methods=['GET', 'POST'])
class KeyAssoc(Resource):
    # Client sends a set or remove with the hash
    # TODO: Validate that this client owns that hash
    def post(self, key_hash):
        loaded = True
        try:
            args = request.values
        except:
            loaded = False
        if not loaded: # Don't want to abort in except
            abort(400)
        if 'method' not in args or (args['method'] != 'set' and args['method'] != 'remove'):
            abort(400, message='method should be set or remove')
        if 'port' not in args:
            abort(400, message='no port')
        if 'host' not in args:
            abort(400, message='no host')
        if args['method'] == 'set':
            associations[key_hash] = (args['host'], args['port'])  # TODO: Validate that host is an IP or FQDM and port is int < 65535
        else:
            del associations[key_hash]
        return 200

    # Get the host and port of the hash, or 404 if not current
    def get(self, key_hash):
        if key_hash not in associations:
            abort(404)
        return {'host': associations[key_hash][0], 'port': associations[key_hash][1]}

if __name__ == "__main__":
    app.run(host="0.0.0.0",port=1234)