import pytest
import streamlit as st
from modes import set_mode, OFFLINE_SAFE, LIVE_ANALYSIS, require_offline, require_live, MODE_KEY

@pytest.fixture(autouse=True)
def setup_streamlit_session():
    if MODE_KEY not in st.session_state:
        st.session_state[MODE_KEY] = OFFLINE_SAFE
    yield
    st.session_state[MODE_KEY] = OFFLINE_SAFE

def test_require_offline_passes_when_offline():
    st.session_state[MODE_KEY] = OFFLINE_SAFE
    
    @require_offline
    def dummy_func():
        return "success"
        
    assert dummy_func() == "success"

def test_require_offline_fails_when_live():
    st.session_state[MODE_KEY] = LIVE_ANALYSIS
    
    @require_offline
    def dummy_func():
        return "success"
        
    with pytest.raises(RuntimeError):
        dummy_func()

def test_require_live_passes_when_live():
    st.session_state[MODE_KEY] = LIVE_ANALYSIS
    
    @require_live
    def dummy_func():
        return "success"
        
    assert dummy_func() == "success"

def test_require_live_fails_when_offline():
    st.session_state[MODE_KEY] = OFFLINE_SAFE
    
    @require_live
    def dummy_func():
        return "success"
        
    with pytest.raises(RuntimeError):
        dummy_func()
