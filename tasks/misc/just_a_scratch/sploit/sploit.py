import json
from copy import deepcopy


def transform_sprite_script(sprite):
    sprite = deepcopy(sprite)

    start_x, start_y = 0, 0
    delta_x, delta_y = 0, 0

    new_blocks = {}
    go_to_x_y_block_id = None
    for block_id, block_data in sprite["blocks"].items():
        match block_data["opcode"]:
            case "motion_glidesecstoxy":
                add_x_block_id = block_data["inputs"]["X"][1]
                add_x_block_data = sprite["blocks"][add_x_block_id]
                delta_x += float(add_x_block_data["inputs"]["NUM2"][1][1])

                add_y_block_id = block_data["inputs"]["Y"][1]
                add_y_block_data = sprite["blocks"][add_y_block_id]
                delta_y += float(add_y_block_data["inputs"]["NUM2"][1][1])

            case "motion_gotoxy":
                go_to_x_y_block_id = block_id
                start_x = float(block_data["inputs"]["X"][1][1])
                start_y = float(block_data["inputs"]["Y"][1][1])
                new_blocks[block_id] = block_data

            case "event_whenflagclicked":
                new_blocks[block_id] = block_data

            case "motion_setrotationstyle":
                new_blocks[block_id] = block_data

    assert go_to_x_y_block_id is not None

    start_x += delta_x
    start_y += delta_y

    new_blocks[go_to_x_y_block_id]["inputs"]["X"][1][1] = str(start_x)
    new_blocks[go_to_x_y_block_id]["inputs"]["Y"][1][1] = str(start_y)

    sprite["blocks"] = new_blocks
    return sprite


if __name__ == '__main__':
    with open('./project/project.json', 'r') as f:
        data = json.load(f)

    for i, target in enumerate(data['targets']):
        if not target['isStage']:
            data['targets'][i] = transform_sprite_script(target)

    with open('./project/project.json', 'w') as f:
        json.dump(data, f)
