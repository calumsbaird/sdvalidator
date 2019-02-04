from sdvalidator import *
domains = ['csbaird.com','google.com','github.com']
cache = validate_sd(domains,verbose=True)
import pickle
with open('backup.pickle','wb') as f:
    pickle.dump(cache, f)
