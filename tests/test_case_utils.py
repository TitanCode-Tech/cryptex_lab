import pytest
import streamlit as st
from case_utils import create_case, get_active_case, set_active_case, add_evidence_to_active_case

# Mock session state since tests run headless outside streamlit
@pytest.fixture(autouse=True)
def setup_streamlit_session():
    # Initialize Streamlit session state manually
    for key in ['cases', 'active_case_id']:
        if key in st.session_state:
            del st.session_state[key]
    yield
    for key in ['cases', 'active_case_id']:
        if key in st.session_state:
            del st.session_state[key]

def test_create_and_get_case():
    case_id = create_case("Target A", "0xGUEST", "Ethereum", "Notes")
    active = get_active_case()
    assert active is not None
    assert active['id'] == case_id
    assert active['name'] == "Target A"

def test_add_evidence():
    case_id = create_case("Target B", "0xGUEST", "Ethereum", "Notes")
    add_evidence_to_active_case("file.txt", b"secret data", "Notes about file")
    
    active = get_active_case()
    assert len(active['evidence']) == 1
    assert active['evidence'][0]['filename'] == "file.txt"
