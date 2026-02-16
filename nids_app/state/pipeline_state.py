# nids_app/state/pipeline_state.py

STAGES = [
    "UPLOADED",
    "PREPROCESSED",
    "TRAINED",
    "PREDICTED",
    "HYBRID_DONE",
]


def get_state(request):
    return request.session.get("PIPELINE_STATE", "UPLOADED")


def set_state(request, state):
    if state not in STAGES:
        raise ValueError("Invalid pipeline state")
    request.session["PIPELINE_STATE"] = state


def state_index(state):
    return STAGES.index(state)


def can_access(request, required_state):
    return state_index(get_state(request)) >= state_index(required_state)
