import random

def read_user_agents(filename):
    with open(filename, 'r') as file:
        return [line.strip() for line in file]

def get_random_user_agent(user_agents):
    return random.choice(user_agents)