from models import DevSecOpsAction
from server.devsecops_environment import DevSecOpsEnvironment

def test_task1():
    env = DevSecOpsEnvironment()
    obs = env.reset(task_id=1)
    if obs.build_status != "FAILED":
        print(f"Task 1 Init FAILED expected, got {obs.build_status}. StdErr:\n{obs.build_stderr}")
    
    # Action: update package
    env.step(DevSecOpsAction(
        action_type="update_package", 
        package_name="requests", 
        new_version_specifier="==2.31.0"
    ))
    
    # Action: run validation
    obs = env.step(DevSecOpsAction(action_type="run_validation"))
    if obs.build_status != "SUCCESS":
        print(f"Task 1 Patch SUCCESS expected, got {obs.build_status}. StdErr:\n{obs.build_stderr}")
        assert False

def test_task2():
    env = DevSecOpsEnvironment()
    obs = env.reset(task_id=2)
    
    # Initial state should FAIL due to version collision
    if obs.build_status != "FAILED":
        print(f"Task 2 Init: Expected FAILED, got {obs.build_status}")
    else:
        print("Task 2 Init: Correctly FAILED with version collision")

    # Fix: remove the conflicting urllib3 direct pin
    # botocore==1.29.0 needs urllib3<1.27, so we remove the urllib3>=2.0 constraint
    env.step(DevSecOpsAction(
        action_type="remove_package",
        package_name="urllib3"
    ))

    # Validate the fix
    obs = env.step(DevSecOpsAction(action_type="run_validation"))
    if obs.build_status != "SUCCESS":
        print(f"Task 2 Fix FAILED: Expected SUCCESS, got {obs.build_status}. StdErr:\n{obs.build_stderr}")
        assert False
    else:
        print(f"Task 2 Fix: Build SUCCESS. Reward: {obs.reward}")

    # Grade the task
    score = env.grade()
    print(f"Task 2 Grade: {score}")
    assert score == 1.0, f"Expected score 1.0, got {score}"
    print("Task 2 PASSED")

def test_task3():
    env = DevSecOpsEnvironment()
    obs = env.reset(task_id=3)

    # Initial state should BUILD successfully but have CVEs
    if obs.build_status != "SUCCESS":
        print(f"Task 3 Init: Expected SUCCESS, got {obs.build_status}. StdErr:\n{obs.build_stderr}")
        assert False
    else:
        print(f"Task 3 Init: Build SUCCESS but CVEs present: {len(obs.cve_report)}")
    assert len(obs.cve_report) > 0, "Expected initial Task 3 CVEs to be present"

    # Grade before fix - should be 0.5 (builds but has CVEs)
    score_before = env.grade()
    print(f"Task 3 Grade before fix: {score_before}")

    # Fix: upgrade requests to 2.31.0 which pulls in safe certifi
    env.step(DevSecOpsAction(
        action_type="update_package",
        package_name="requests",
        new_version_specifier="==2.31.0"
    ))

    # Also upgrade certifi directly to safe version
    env.step(DevSecOpsAction(
        action_type="update_package",
        package_name="certifi",
        new_version_specifier="==2023.11.17"
    ))

    # Validate the fix
    obs = env.step(DevSecOpsAction(action_type="run_validation"))
    print(f"Task 3 After fix: Build={obs.build_status}, CVEs={len(obs.cve_report)}, Reward={obs.reward}")

    # Grade after fix - should be 1.0
    score_after = env.grade()
    print(f"Task 3 Grade after fix: {score_after}")
    assert score_after == 1.0, f"Expected score 1.0, got {score_after}"
    print("Task 3 PASSED")

if __name__ == "__main__":
    test_task1()
    print("----")
    test_task2()
    print("----")
    test_task3()
    print("ALL TESTS COMPLETE")
