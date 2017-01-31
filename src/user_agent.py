import json

json_file = "agent_list.json"


def get_user_agents():
    with open(json_file) as data_file:
        data = json.load(data_file)
    user_agents = [x["agent_string"] for x in data]
    return user_agents
