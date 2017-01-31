import json
import os

folder = os.path.dirname(__file__) + os.sep
json_file = folder + "agent_list.json"


def get_user_agents():
    with open(json_file) as data_file:
        data = json.load(data_file)
    user_agents = [x["agent_string"] for x in data]
    if len(user_agents) < 1:
        return None
    return user_agents
