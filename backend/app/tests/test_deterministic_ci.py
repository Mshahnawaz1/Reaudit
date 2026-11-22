import yaml

from backend.app.deterministic.ci_rules import analyze_workflow

SHA = "a" * 40


def rules(text):
    return {h.rule_id: h for h in analyze_workflow(".github/workflows/x.yml", text)}


def all_hits(text, rid):
    return [h for h in analyze_workflow(".github/workflows/x.yml", text) if h.rule_id == rid]


def wf(on="push", jobs=None, perms="permissions: read-all\n"):
    return f"name: t\non: {on}\n{perms}jobs:\n{jobs or '  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n'}"


def test_ci001():
    pos = wf("pull_request_target", "  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@" + SHA + "\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n")
    h = rules(pos)["CI-001"]
    assert h.line == 10 and "head.sha" in h.snippet and h.severity == "critical"
    neg = wf("pull_request_target", "  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@" + SHA + "\n")
    assert "CI-001" not in rules(neg)
    neg2 = wf("pull_request", "  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@" + SHA + "\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n")
    assert "CI-001" not in rules(neg2)


def test_ci002():
    pos = wf("pull_request", "  b:\n    runs-on: ubuntu-latest\n    steps:\n      - name: x\n        run: |\n          echo hello\n          echo \"${{ github.event.pull_request.title }}\"\n")
    h = rules(pos)["CI-002"]
    assert h.line == 11 and "pull_request.title" in h.snippet
    assert "CI-002" in rules(wf("push", "  b:\n    runs-on: x\n    steps:\n      - run: echo ${{ github.head_ref }}\n"))
    safe = wf("pull_request", "  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo \"$T ${{ github.event.pull_request.number }} ${{ github.sha }}\"\n        env:\n          T: ${{ github.event.pull_request.title }}\n")
    assert "CI-002" not in rules(safe)


def test_ci003():
    steps = "  b:\n    runs-on: x\n    steps:\n      - uses: {u}\n"
    h = rules(wf(jobs=steps.format(u="thirdparty/act@v1")))["CI-003"]
    assert h.severity == "medium" and h.line == 8 and "thirdparty/act@v1" in h.snippet
    assert rules(wf(jobs=steps.format(u="actions/checkout@v4")))["CI-003"].severity == "low"
    assert rules(wf(jobs=steps.format(u="thirdparty/act@main")))["CI-003"].severity == "high"
    assert "CI-003" not in rules(wf(jobs=steps.format(u="thirdparty/act@" + SHA)))
    assert "CI-003" not in rules(wf(jobs=steps.format(u="./local")))


def test_ci004():
    h = rules(wf(perms=""))["CI-004"]
    assert h.line == 4 and h.snippet == "b:"
    assert "CI-004" not in rules(wf())
    jobperm = wf(perms="", jobs="  b:\n    runs-on: x\n    permissions:\n      contents: read\n    steps:\n      - run: a\n")
    assert "CI-004" not in rules(jobperm)


def test_ci005():
    assert rules(wf(perms="permissions: write-all\n"))["CI-005"].severity == "high"
    broad = "permissions:\n  contents: write\n  packages: write\n  issues: write\n"
    assert "CI-005" in rules(wf(perms=broad))
    assert "CI-005" not in rules(wf(perms="permissions:\n  contents: read\n"))
    jobwa = wf(perms="permissions: read-all\n", jobs="  b:\n    runs-on: x\n    permissions: write-all\n    steps:\n      - run: a\n")
    assert "CI-005" in rules(jobwa)


def test_ci006():
    jobs = "  b:\n    runs-on: x\n    steps:\n      - run: ./deploy.sh\n        env:\n          K: ${{ secrets.DEPLOY_KEY }}\n"
    h = rules(wf("pull_request_target", jobs))["CI-006"]
    assert h.line == 10 and "secrets.DEPLOY_KEY" in h.snippet
    assert "CI-006" not in rules(wf("push", jobs))
    assert "CI-006" not in rules(wf("pull_request_target", jobs.replace("secrets.DEPLOY_KEY", "secrets.GITHUB_TOKEN")))


def test_ci007():
    j = "  b:\n    runs-on: x\n    steps:\n      - run: curl -sSL https://x.io/i.sh | sudo bash\n"
    assert rules(wf(jobs=j))["CI-007"].line == 8
    assert "CI-007" in rules(wf(jobs=j.replace("curl -sSL https://x.io/i.sh | sudo bash", "wget -qO- https://x.io/i.sh | sh")))
    assert "CI-007" not in rules(wf(jobs=j.replace("| sudo bash", "-o i.sh")))


def test_ci008():
    j = "  b:\n    runs-on: [self-hosted, linux]\n    steps:\n      - run: a\n"
    assert rules(wf("pull_request", j))["CI-008"].line == 6
    assert "CI-008" not in rules(wf("push", j))
    assert "CI-008" not in rules(wf("pull_request", j.replace("[self-hosted, linux]", "ubuntu-latest")))


def test_unparseable():
    h = rules("on: [\n  bad: : :\n")["CI-000"]
    assert h.severity == "info"


def test_line_numbers_match_file_text():
    text = wf("pull_request_target", "  b:\n    runs-on: x\n    steps:\n      - uses: evil/act@v1\n      - run: echo ${{ github.head_ref }}\n")
    lines = text.splitlines()
    for h in analyze_workflow(".github/workflows/x.yml", text):
        assert h.snippet in lines[h.line - 1]
    yaml.safe_load(text)
