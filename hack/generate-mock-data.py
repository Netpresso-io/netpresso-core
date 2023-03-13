import random
from datetime import datetime, timedelta

# Function to generate a random timestamp in the last week
def random_timestamp():
    now = datetime.now()
    start_of_week = now - timedelta(days=7)
    return start_of_week + timedelta(seconds=random.randint(0, 604800))

# Generate a list of 100 tuples with random timestamp and random integer between 1 and 100
data = [(str(int(random_timestamp().timestamp()))+"000000000", random.randint(1, 100)) for i in range(100)]

thefile = open('data.txt', 'w')
for row in data:
    thefile.write(f'speed-test speed={row[1]} {row[0]}\n')