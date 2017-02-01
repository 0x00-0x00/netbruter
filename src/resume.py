import os
from netbruter.argv import retrieve_command_line


def restore_script(script_file="resume.sh"):
    """
    If 'resume.sh' does not exists, create it to easily resume the attack
    :param script_file:
    :return: None
    """
    if os.path.isfile(script_file):
        return None

    data = "#!/bin/bash\n{0}".format(retrieve_command_line())
    with open(script_file, "w") as f:
        f.write(data)
    return
