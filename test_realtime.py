from client import DevSecOpsEnvClient
from models import DevSecOpsAction
import time

def test_realtime_loop():
    print("Connecting to OpenEnv WebSocket server at http://localhost:8000...")
    
    # 'with' handles the WebSocket handshake and teardown automatically!
    with DevSecOpsEnvClient(base_url="http://localhost:8000").sync() as env:
        print("[SUCCESS] Connected securely over WebSockets!\n")
        
        print("--- Testing Task 1 (Dead Link) ---")
        start_time = time.time()
        
        # Reset requests a new environment session state over WS
        result = env.reset(task_id=1)
        print(f"[{time.time()-start_time:.3f}s] Initial Status: {result.observation.build_status}")
        
        # Send a rapid series of steps over the open WebSocket
        print("\nStreaming actions over WebSockets...")
        
        result = env.step(DevSecOpsAction(
            action_type="update_package", 
            package_name="requests", 
            new_version_specifier="==2.31.0"
        ))
        
        result = env.step(DevSecOpsAction(action_type="run_validation"))
        print(f"[{time.time()-start_time:.3f}s] After Patch Status: {result.observation.build_status}")
        print(f"Reward calculated in realtime: {result.reward}")
        
        result = env.step(DevSecOpsAction(action_type="submit_final_manifest"))
        print(f"[{time.time()-start_time:.3f}s] Final Reward with Bonus: {result.reward}")
        print("Done boolean flag:", result.done)

if __name__ == "__main__":
    test_realtime_loop()
