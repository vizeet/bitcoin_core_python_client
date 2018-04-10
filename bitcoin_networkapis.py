import pycurl
from io import BytesIO
import json
import datetime
import pandas as pd

myaddress = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

btcval = 100000000.0 # in santoshis

block_time_in_min = 10
block_time_in_sec = block_time_in_min*60

def getBalance(address: str):
        strbuf = BytesIO()
        getreq = pycurl.Curl()
        getreq.setopt(getreq.URL, "https://blockchain.info/unspent?active=%s" % (address))
        getreq.setopt(getreq.WRITEDATA, strbuf)
        getreq.setopt(getreq.HTTPHEADER, ['Accept: application/json'])
        getreq.perform()
        getreq.close()

        balance = 0.0
#        print("getreq = %s" % (getreq.getvalue()))
        allunspenttx = json.loads(strbuf.getvalue())['unspent_outputs']
        for eachtx in allunspenttx:
                balance += eachtx['value']

        return balance

def getTxnHistoryOfAddress(address: str):
        strbuf = BytesIO()
        getreq = pycurl.Curl()
        getreq.setopt(getreq.URL, "https://blockchain.info/address/%s?format=json" % (address))
        getreq.setopt(getreq.WRITEDATA, strbuf)
        getreq.setopt(getreq.HTTPHEADER, ['Accept: application/json'])
        getreq.perform()
        getreq.close()

        new_txn_list = []
        alltxns = json.loads(strbuf.getvalue())['txs']
        for eachtxn in alltxns:
                new_txn = {}
                input_list = eachtxn['inputs']
                input_value = 0
                address_input_value = 0
                for each_input in input_list:
                        input_value += each_input['prev_out']['value']
                        if each_input['prev_out']['addr'] == address:
                                address_input_value += each_input['prev_out']['value']

                output_list = eachtxn['out']
                output_value = 0
                address_output_value = 0
                for each_output in output_list:
                        output_value += each_output['value']
                        if each_output['addr'] == address:
                                address_output_value += each_output['value']

                if address_input_value > address_output_value:
                        new_txn['credit_in_btc'] = (address_input_value - address_output_value) / btcval
                else:
                        new_txn['debit_in_btc'] = (address_output_value - address_input_value) / btcval
                        
                network_fees = input_value - output_value
                new_txn['network_fees'] = network_fees / btcval
                new_txn['network_fees_in_inr'] = new_txn['network_fees'] * getCurrentSellPriceInInr()
                dt = datetime.datetime.fromtimestamp(eachtxn['time'])
                new_txn['date_time'] = dt.strftime("%d-%B-%Y %H:%M:%S")
                new_txn_list.append(new_txn)
        return new_txn_list

def getCurrentBlockHeight():
        strbuf = BytesIO()
        getreq = pycurl.Curl()
        getreq.setopt(getreq.URL, "https://blockchain.info/blocks?format=json")
        getreq.setopt(getreq.WRITEDATA, strbuf)
        getreq.setopt(getreq.HTTPHEADER, ['Accept: application/json'])
        getreq.perform()
        getreq.close()

        current_block_height = json.loads(strbuf.getvalue())['blocks'][0]['height']

        return current_block_height

def getTxCountInBlock(block_height: int):
        strbuf = BytesIO()
        getreq = pycurl.Curl()
        getreq.setopt(getreq.URL, "https://blockchain.info/block-height/%d?format=json" % (block_height))
        getreq.setopt(getreq.WRITEDATA, strbuf)
        getreq.setopt(getreq.HTTPHEADER, ['Accept: application/json'])
        getreq.perform()
        getreq.close()
        
        txlist = json.loads(strbuf.getvalue())['blocks'][0]['tx']

        return len(txlist)

#def getListOfTxnsOnAddress(address: str):
#
#def getInputBitcoinInTx(txn: str):
#        
#def getOutputBitcoinInTx(txn: str):
#
#def getChangeInTx(txn: str):
#
#def getNetworkFeesInTxn(txn: str):

def getTxRate(tx_count_in_block: int):

        return tx_count_in_block/block_time_in_sec
#        return block_time_in_sec/tx_count_in_block

def getAverageTxRateInLast24Hrs():
        current_block_height = getCurrentBlockHeight()

        min_in_a_day = 60*24
        blocks_in_a_day = int(min_in_a_day/block_time_in_min)

        sum_tx_rate = 0
        print("Transaction rate::")
        for block_height in range(current_block_height - blocks_in_a_day, current_block_height):
                tx_count = getTxCountInBlock(block_height)
                tx_rate = getTxRate(tx_count)
                sum_tx_rate += tx_rate

                print("block height %d          ===>            Tx Rate %.6f" % (block_height, tx_rate))

        average_tx_rate = sum_tx_rate / blocks_in_a_day

        return average_tx_rate

def getAverageTxRateInLastWeek():
        current_block_height = getCurrentBlockHeight()

        min_in_a_week = 60*24*7
        blocks_in_a_week = int(min_in_a_week/block_time_in_min)

        sum_tx_rate = 0
        print("Transaction rate::")
        for block_height in range(current_block_height - blocks_in_a_week, current_block_height):
                tx_count = getTxCountInBlock(block_height)
                tx_rate = getTxRate(tx_count)
                sum_tx_rate += tx_rate

                print("block height %d          ===>            Tx Rate %.6f" % (block_height, tx_rate))

        average_tx_rate = sum_tx_rate / blocks_in_a_week

        return average_tx_rate

def getAverageTxRateInLastMonth():
        current_block_height = getCurrentBlockHeight()

        min_in_a_month = 60*24*7
        blocks_in_a_month = int(min_in_a_month/block_time_in_min)

        sum_tx_rate = 0
        print("Transaction rate::")
        for block_height in range(current_block_height - blocks_in_a_month, current_block_height):
                tx_count = getTxCountInBlock(block_height)
                tx_rate = getTxRate(tx_count)
                sum_tx_rate += tx_rate

                print("block height %d          ===>            Tx Rate %.6f" % (block_height, tx_rate))

        average_tx_rate = sum_tx_rate / blocks_in_a_month

        return average_tx_rate

def getCurrentNetworkHashRate():
        strbuf = BytesIO()
        getreq = pycurl.Curl()
        getreq.setopt(getreq.URL, "https://blockchain.info/q/hashrate")
        getreq.setopt(getreq.WRITEDATA, strbuf)
        getreq.setopt(getreq.HTTPHEADER, ['Accept: text/plain'])
        getreq.perform()
        getreq.close()

        current_network_hash_rate = int(strbuf.getvalue()) * 10**9

        return current_network_hash_rate

def getCurrentBlockReward():
        strbuf = BytesIO()
        getreq = pycurl.Curl()
        getreq.setopt(getreq.URL, "https://blockchain.info/q/bcperblock")
        getreq.setopt(getreq.WRITEDATA, strbuf)
        getreq.setopt(getreq.HTTPHEADER, ['Accept: text/plain'])
        getreq.perform()
        getreq.close()

        block_reward_abs = int(strbuf.getvalue())

        block_reward = block_reward_abs / btcval

        return block_reward

def getCurrentBuyPriceInInr():
        strbuf = BytesIO()
        getreq = pycurl.Curl()
        getreq.setopt(getreq.URL, "https://www.zebapi.com/api/v1/market/ticker-new/btc/inr")
        getreq.setopt(getreq.WRITEDATA, strbuf)
        getreq.setopt(getreq.HTTPHEADER, ['Accept: application/json'])
        getreq.perform()
        getreq.close()

        current_buy_rate_in_inr = json.loads(strbuf.getvalue())['buy']

        return current_buy_rate_in_inr

def getCurrentSellPriceInInr():
        strbuf = BytesIO()
        getreq = pycurl.Curl()
        getreq.setopt(getreq.URL, "https://www.zebapi.com/api/v1/market/ticker-new/btc/inr")
        getreq.setopt(getreq.WRITEDATA, strbuf)
        getreq.setopt(getreq.HTTPHEADER, ['Accept: application/json'])
        getreq.perform()
        getreq.close()

        current_buy_rate_in_inr = json.loads(strbuf.getvalue())['sell']

        return current_buy_rate_in_inr

def getCurrentValueOfBitcoinInAddressInInr(address: str):
        btc = getBalance(address) / btcval
        price_in_inr = getCurrentSellPriceInInr()
        value = btc * price_in_inr
        return value

def getUnconfirmedTransactionCount():
        strbuf = BytesIO()
        getreq = pycurl.Curl()
        getreq.setopt(getreq.URL, "https://blockchain.info/q/unconfirmedcount")
        getreq.setopt(getreq.WRITEDATA, strbuf)
        getreq.setopt(getreq.HTTPHEADER, ['Accept: application/json'])
        getreq.perform()
        getreq.close()

        unconfirmed_transaction_count = int(strbuf.getvalue())

        return unconfirmed_transaction_count


def convertToRupeeFormat(num: float):
        numstr = "%.2f" % (num)
#        print("numstr = %s" % (numstr))
#        print("numstr len = %s" % (len(numstr)))

        commaloc = 6
        while commaloc < len(numstr):
                numstr = numstr[:-commaloc] + ',' + numstr[-commaloc:]
                commaloc += 3
        rupees = "\u20B9%s" % (numstr)
        return rupees

electricity_rates = {"rate_slabs": [{"min": 1, "max": 30, "unit_price": 3.25}, {"min": 31, "max": 100, "unit_price": 4.7}, {"min": 101, "max": 200, "unit_price": 6.25}, {"min": 201, "unit_price": 7.3}]}

def getPriceFromUnit(unit: float):
        rate_slabs = electricity_rates['rate_slabs']
        price = 0
        for slab in rate_slabs:
                if slab['min'] > unit:
                        countinue
                elif ('max' in slab and slab['max']) > unit or 'max' not in slab:
#                        if 'max' in slab:
#                                print("min = %.2f, max = %.2f, unit = %.2f" % (slab['min'], slab['max'], unit))
#                        else:
#                                print("min = %.2f, unit = %.2f" % (slab['min'], unit))
                        price += (unit - slab['min']) * slab['unit_price']
                else:
                        price += (slab['max'] - slab['min']) * slab['unit_price']
        return price

def getUnitFromPower(power: float):
        unit = power * 24 * 30 / 1000
        return unit

def getBlockMiningRatePer10Min(hashrate: int):
        network_hashrate = getCurrentNetworkHashRate()
        block_mining_rate = hashrate/network_hashrate
        return block_mining_rate

def getBitcoinMiningRate(hashrate: int):
        block_mining_rate = getBlockMiningRatePer10Min(hashrate)
        mining_reward = getCurrentBlockReward()
        bitcoin_mining_rate = block_mining_rate * mining_reward
        return bitcoin_mining_rate

def getMiningPowerExpense(power: float):
        unit = getUnitFromPower(power)
        expense = getPriceFromUnit(unit)
        return expense

def getBitcoinMinedPerMonth(hashrate: int):
        bitcoin_mined_per_month = getBitcoinMiningRate(hashrate) * 6 * 24 * 30
        return bitcoin_mined_per_month

def miningReturn(power: float, hashrate: int):
        expense = getMiningPowerExpense(power)
        bitcoin_mined_per_month = getBitcoinMinedPerMonth(hashrate)
        revenue = bitcoin_mined_per_month * getCurrentSellPriceInInr()
        profit = revenue - expense
        return profit

def costOfMiningBitcoin(power: float, hashrate: int):
        unit = getUnitFromPower(power)
        price_per_month = getPriceFromUnit(unit)
        bitcoin_mined_per_month = getBitcoinMiningRate(hashrate) * 6 * 24 * 30
        cost_of_mining_bitcoin = price_per_month/bitcoin_mined_per_month
        return cost_of_mining_bitcoin

if __name__ == "__main__":
        balance = getBalance(myaddress) / btcval
        print("Current Bitcoin balance = %.8f at Address = %s" % (balance, myaddress))

        value = getCurrentValueOfBitcoinInAddressInInr(myaddress)
        print("Current Value of Bitcoin = %.2f for Address = %s" % (value, myaddress))

        current_block_height = getCurrentBlockHeight()
        print("current block height = %d" % (current_block_height))

        tx_count_in_last_block = getTxCountInBlock(current_block_height)
        print("Number of transactions in last block = %d" % (tx_count_in_last_block))

        tx_rate = getTxRate(tx_count_in_last_block)
        print("Current transaction rate = %.6f" % (tx_rate))

#        average_tx_rate = getAverageTxRateInLast24Hrs()
#        print("Average Transaction Rate in last 24 Hrs = %.6f" % (average_tx_rate))

        current_network_hash_rate = getCurrentNetworkHashRate()
        print("Current Network Hash Rate = %d" % (current_network_hash_rate))

        block_reward = getCurrentBlockReward()

        print("Current Block Reward = %.8f" % (block_reward))

        current_buy_rate_in_inr = getCurrentBuyPriceInInr()

        current_buy_rate_in_rupees = convertToRupeeFormat(current_buy_rate_in_inr)

        print("Current Buy Rate in Indian Rupees = %s" % (current_buy_rate_in_rupees))

        miner_hashrate = 13.5 * 10**12
        print("Miner hashrate = %d" % (miner_hashrate))

        miner_power = 1323
        print ("Miner Power in Watt = %f" % (miner_power))

        expense = getMiningPowerExpense(miner_power)
        print ("Miner Power Expense Per Month = %.2f" % (expense))

        bitcoin_mined_per_month = getBitcoinMinedPerMonth(miner_hashrate)
        print("Bitcoin Mined Per Month = %.8f from Miner with hashrate = %d" % (bitcoin_mined_per_month, miner_hashrate))

        mining_return = miningReturn(miner_power, miner_hashrate)
        print("Mining Return Per Month = %s" % (mining_return))

        cost_of_mining_bitcoin = costOfMiningBitcoin(miner_power, miner_hashrate)
        print("Cost of Mining Bitcoin = %.2f" % (cost_of_mining_bitcoin))

        unconfirmed_transaction_count = getUnconfirmedTransactionCount()
        print("Total Unconfirmed Transaction Count = %d" % (unconfirmed_transaction_count))

        txn_history = getTxnHistoryOfAddress(myaddress)
        txn_history_table = pd.DataFrame(txn_history)
        print("Transaction History::\n%s" % (txn_history_table))
