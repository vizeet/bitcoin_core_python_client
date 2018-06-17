import requests

def getUnspentTxnList(address: str):
        url = 'https://blockchain.info/unspent?active=%s' % address
        response = requests.get(url)
        jsonobj = json.loads(response.text)
        return jsonobj

# just be little smart here
def selectUnspentTxnsForAmount(jsonobj, amount: str):
        pass

def askNewAddress():
        pass

def 
