import json
import sys

src = sys.argv[1]

with open(src) as f:
    a = json.load(f)

j = json.dumps([dict({'public_id': 'id-{}'.format(i)}, **x) for (i, x) in enumerate(a)])

with open(src, 'w') as f:
    f.write(j)
