import os
import requests
import json
import logging
from elasticsearch import Elasticsearch, NotFoundError
from datetime import datetime
from elasticsearch.helpers import scan
from dotenv import load_dotenv

load_dotenv()
ELASTIC_PASSWORD  = os.environ.get("ELASTIC_PASSWORD")
CLOUD_ID  = os.environ.get("CLOUD_ID")
# Define your Elasticsearch client here
client = Elasticsearch(
    cloud_id=CLOUD_ID,
    basic_auth=("elastic", ELASTIC_PASSWORD)
)
client.info()

def fetch_data():
             
        CRYPTOPUNKS_KEY = os.environ.get("CRYPTOPUNKS_KEY")
        MUTANTAPE_KEY = os.environ.get("MUTANTAPE_KEY")
        ETHERSCAN_KEY = os.environ.get("ETHERSCAN_KEY")
     

        # Cryptopunks
        cryptopunks_url = f'https://api.etherscan.io/api?module=account&action=txlist&address={CRYPTOPUNKS_KEY}&startblock=0&endblock=99999999&sort=asc&apikey={ETHERSCAN_KEY}'
        cryptopunks_response = requests.get(cryptopunks_url)
        cryptopunks_data = json.loads(cryptopunks_response.text)
        # logging.info("Cryptopunks Data: %s", cryptopunks_data)
        process_and_store_data(cryptopunks_data, "Cryptopunks")

        # MutantApe
        mutantape_url = f'https://api.etherscan.io/api?module=account&action=txlist&address={MUTANTAPE_KEY}&startblock=0&endblock=99999999&sort=asc&apikey={ETHERSCAN_KEY}'
        mutantape_response = requests.get(mutantape_url)
        mutantape_data = json.loads(mutantape_response.text)
        # logging.info("MutantApe Data: %s", mutantape_data)
        process_and_store_data(mutantape_data, "MutantApe")

        return "Data fetched and processed successfully."


def process_and_store_data(data, project_name):
    try:
        print("API Response Data:", data)
        hourly_gas_fees = {}  # To store average gas fees per hour
        
        if 'result' in data and isinstance(data['result'], list):
            for entry in data['result']:
                try:
                    print("Entry:", entry)
                    timestamp = int(entry.get('timeStamp', 0))
                    gas_price = int(entry.get('gasPrice', 0)) / 1e9  # Convert from Gwei to ETH
                    gas_fee = gas_price * int(entry.get('gasUsed', 0)) / 1e18  # Convert to ETH
                    hour = datetime.utcfromtimestamp(timestamp).hour

                    if hour not in hourly_gas_fees:
                        hourly_gas_fees[hour] = []

                    hourly_gas_fees[hour].append(gas_fee)
                except Exception as entry_error:
                    print("Error processing entry:", entry_error)

            # Calculate average gas fees for each hour
            avg_gas_fees = {hour: sum(fees) / len(fees) for hour, fees in hourly_gas_fees.items()}

            # Get current Ether-to-USD exchange rate
            eth_to_usd_exchange_rate = get_eth_to_usd_exchange_rate()

            avg_gas_fees_usd = {hour: avg_fee * eth_to_usd_exchange_rate for hour, avg_fee in avg_gas_fees.items()}

            # Prepare a list of documents for Elasticsearch indexing
            docs_to_index = []
            for hour, avg_fee_usd in avg_gas_fees_usd.items():
                entry = data['result'][0]  # Use the first entry to get the timestamp
                timestamp = int(entry.get('timeStamp', 0))
                timestamp_str = datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
                avg_fee_eth = avg_gas_fees[hour]  # Get the average gas fee in ETH for the current hour

                # Prepare the document to be indexed in Elasticsearch
                doc = {
                    'project_name': project_name,
                    'hour': hour,
                    'timestamp': timestamp_str,
                    'average_gas_fee_eth': avg_fee_eth,
                    'average_gas_fee_usd': avg_fee_usd
                }
                docs_to_index.append(doc)

            # Index the documents in Elasticsearch
            index_name = "gas-fees-index"
            for doc in docs_to_index:
                response = client.index(index=index_name, body=doc)
                logging.info("Indexed document successfully: %s", response)

    except NotFoundError:
        logging.error("Index not found. Ensure the index exists before indexing data.")
    except Exception as process_error:
        print("Error processing data:", process_error)


