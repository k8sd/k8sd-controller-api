import io
import os
from flask import Flask, request
from flask import send_file, render_template, render_template_string
from pathlib import Path
import string
import subprocess
import random
import logging
import json

app = Flask(__name__)
CONFIG = {
    "whitelisting_enabled": False,
    "whitelist_ip_cidrs": [],
    "cluster": "k8s",
    "controller_ip": "100.64.0.1",
    "admin_api_key": "".join(
        random.SystemRandom().choice(string.ascii_uppercase + string.digits)
        for _ in range(25)
    ),
    "api_key": "".join(
        random.SystemRandom().choice(string.ascii_uppercase + string.digits)
        for _ in range(25)
    ),
}


## Controller -
@app.route("/create/<domain>")
def CreateCluster(domain, public_key=None, managed_credentials=False):
    """Initial call to create a cluster.
    This spins up an instances with:
    - headscale
    - headscale config
    - headscale service setup
    - k3s master setup
    - k3s proxy setup

    If user chooses the option to manage credentials, secrets for headscale are stored.

    """
    return render_template("master-launch.sh", controller_domain=domain)


@app.route("/claim/<key>")
def ClaimCluster(key):
    if not AuthenticateOneTimeConfigKey(key):
        return {"error": "Access Denied"}
    config = GetConfig()
    return {
        "admin_api_key": config["admin_api_key"],
        "node_join_url": "https://%s/cluster/connect/worker/%s"
        % (GetControllerDomain(), config["api_key"]),
        "kubeconfig": GetInitialKubeconfig(),
    }


@app.route("/mine/update-kubeconfig")
def GetInitialKubeconfigAsUpdate():
    pass


@app.route("/connect/interactive/<node_identifier>")
def InteractiveConnectNode(node_identifier):
    """Starts up a new node and allows them to not provide arguments.
    Requires interactive configuration by the admin.
    """
    pass


@app.route("/connect/worker/<key>")
def ConnectNode(key):
    """When a new node is started up, it's cloud-init calls this endpoint.
    Returns a full configuration script that is intended to be executed.
    This is expected to be an automated endpoint.
    There is another endpoint that is interactive, or allows the admin to configure via controller UI.
    """

    if not ValidKey(key, admin=False):
        raise Exception("Bad authorization")

    config = GetConfig()
    # Currently static, used in the TN namespace.
    cluster = config["cluster"]

    # Use headscale to generate a pre-auth key for this node. Make it 1 time use, and set tags.
    # Currently default tags, everything is "worker".
    args = request.args.to_dict()

    # We should check that the hostname is not taken
    # args.get("hostname")

    tags = []
    additional_tailscale_args = []

    # TODO: We need tag validation once we use them for something
    # TODO: We need to do validation on clustername and key
    if "environment" in args:
        tags.append(args["environment"])

    if "region" in args:
        tags.append(args["region"])

    if "exit" in args and args["exit"]:
        tags.append("egress")
        # TODO: Validate that the exit node is one we actually want to route outbound through
        additional_tailscale_args.append("--advertise-exit-node")

    # Cluster members advertise the routes
    cluster_cidrs = "10.42.0.0/16,10.43.0.0/16"
    additional_tailscale_args.append(
        '--advertise-routes "%s" --accept-routes' % cluster_cidrs
    )

    # TODO: something to support egress outbound
    # --exit-node to be set if we want to route outbound traffic out of an outbound proxy.
    # TODO: something to support advertising routes automatically for things like AWS SES.
    # --advertise-routes

    # For now there are some defaults:
    controller_domain = GetControllerDomain()

    controller_private_ip = config["controller_ip"]
    tailscale_preauth_key = GeneratePreauthKey(namespace=cluster, tags=tags)

    with open("/data/k3s/server/agent-token", "r") as agent_token_file:
        k3s_token = agent_token_file.read().strip()

    additional_tailscale_args = " ".join(additional_tailscale_args)
    ##On the k8s api need to label node-role.kubernetes.io/worker=worker - nodes cant select it for themselves
    return render_template(
        "worker-launch.sh",
        controller_domain=controller_domain,
        controller_private_ip=controller_private_ip,
        tailscale_preauth_key=tailscale_preauth_key,
        k3s_install_token=k3s_token,
        tailscale_args=additional_tailscale_args,
        whitelisted_ips=config["whitelist_ip_cidrs"],
        ip_whitelisting=config["whitelisting_enabled"],
    )


@app.route("/applications/headscale/<architecture>")
def get_headscale_binary(architecture, version="0.17.0"):
    # filename = 'uploads\\123.jpg'
    with open("binaries/headscale_%s_linux_%s" % (version, architecture), "rb") as f:
        return send_file(io.BytesIO(f.read()), mimetype="application/octet-stream")


@app.route("/config/headscale/<key>")
def get_headscale_config(key):
    return render_template("headscale_config.yaml", name=key)


@app.route("/config/kubernetes/<key>")
def get_kubernetes_config(key, override_permissions=False):
    """Returns the local kubectl configuration.
    Expected to be run after initializing the cluster with a 1-time code.
    """

    config = GetConfig()
    if not (override_permissions or key == config["admin_api_key"]):
        return {"error": "unauthenticated"}
    controller_private_address = "%s:6443" % config["controller_ip"]
    with open("/etc/rancher/k3s/k3s.yaml", "r") as ctl_file:
        kubectl_file = ctl_file.read()
    return kubectl_file.replace(
        controller_private_address, "%s:6445" % GetControllerDomain()
    )


@app.route("/config/ipwhitelist/<option>/<key>", methods=["POST"])
def set_ip_whitelisting(option, key):
    if not ValidKey(key, admin=True):
        return {"error": "unauthorized"}
    enable_options = ["enable", "on", "enabled"]
    disable_options = ["disable", "disabled", "off"]
    if option in enable_options:
        wl_enabled = True
    elif option in disable_options:
        wl_enabled = False
    else:
        return {
            "error": "malformed request, options are: %s"
            % ", ".join(enable_options + disable_options)
        }
    config = GetConfig()
    config["whitelisting_enabled"] = wl_enabled
    SaveConfig()
    return {"whitelisting_enabled": wl_enabled}


@app.route("/config/ipwhitelist/modify/<key>", methods=["POST"])
def modify_ingress_whitelist(key):
    if not ValidKey(key, admin=True):
        return {"error": "unauthorized"}
    change_options = ["add", "remove", "replace"]
    print(request)
    params = request.get_json(force=True)
    print(params)
    if "ip" in params:
        entries = [params["ip"]]
    else:
        entries = params["ips"]
    if params["change"] not in change_options:
        return {
            "error": "malformed request, change options are: %s"
            % ", ".join(change_options)
        }

    config = GetConfig()
    ip_set = set(config["whitelist_ip_cidrs"])
    if params["change"] == "add":
        for ip in entries:
            if "/" not in ip:
                ip = "%s/32" % ip
            ip_set.add(ip)
    elif params["change"] == "remove":
        for ip in entries:
            if "/" not in ip:
                ip = "%s/32" % ip
            ip_set.remove(ip)

    elif params["change"] == "replace":
        ip_set = set()
        for ip in entries:
            if "/" not in ip:
                ip = "%s/32" % ip
            ip_set.add(ip)
    config["whitelist_ip_cidrs"] = list(ip_set)
    SaveConfig()
    response = {
        "status": "success",
        "ip_list": config["whitelist_ip_cidrs"],
    }
    if not config["whitelisting_enabled"] and config["whitelist_ip_cidrs"]:
        response["warning"] = "Whitelisting is disabled but there is a whitelist."
    return response


def GetInitialKubeconfig():
    return get_kubernetes_config("", override_permissions=True)


def GetControllerDomain():
    # For now there are some defaults:
    controller_domain = os.environ.get("K8SD_CONTROLLER_DOMAIN")
    if not controller_domain:
        logging.error("Need to provide a K8SD_CONTROLLER_DOMAIN environment variable")
        config = GetConfig()
        if "controller" not in config or not config["controller"]:
            logging.error(
                "No controller defined in environment or controller-config.json"
            )
            raise Exception("No controller provided")
    SaveConfig()
    return controller_domain


def GeneratePreauthKey(namespace=None, api=None, key=None, tags=[]):
    # headscale_path = "./binaries/headscale_0.17.0_linux_amd64"
    headscale_path = "headscale"
    command = [headscale_path, "authkey", "create", "-o", "json", "-n", namespace]

    if tags:
        command.append("--tags")
        tag_list = []
        for tag in tags:
            tag_list.append("tag:%s" % tag)
        command.append(",".join(tag_list))
    if api and key:
        logging.warning("Using remote headscale %s" % api)
        env = {
            "HEADSCALE_CLI_ADDRESS": "%s:50443" % api,
            "HEADSCALE_CLI_API_KEY": "%s" % key,
        }
    else:
        env = {}

    logging.warn(" ".join(command))
    logging.debug("env: %s" % env)
    try:
        key_command = subprocess.run(
            command, stdout=subprocess.PIPE, text=True, check=True, env=env
        )
    # Creation failed
    except Exception as e:
        raise (e)
        # raise(Exception("Unable to generate preauth key"))
    if key_command.returncode:
        logging.warn(" ".join(command))
        logging.warn("env: %s" % env)
        raise (Exception("Unable to generate preauth key"))
    result = json.loads(key_command.stdout)
    if "error" in result:
        raise (Exception("Unable to generate preauth key: %s" % result["error"]))

    return result["key"]


def AuthenticateOneTimeConfigKey(key):
    """Returns true if this is the first call to fetch the config file."""
    if os.path.exists("one_time_cluster_key") and not os.path.exists(
        "configuration_accessed"
    ):
        # requires one time cluster key to not have been accessed before.
        with open("one_time_cluster_key", "r") as keyfile:
            valid_key = keyfile.read().strip()
        if key == valid_key:
            os.remove("one_time_cluster_key")
            Path("configuration_accessed").touch()
            return True
        return False
    else:
        return False


def ValidKey(key, admin=True):
    """Validates the authentication key passed in to request URLs."""
    config = GetConfig()
    if admin and key == config["admin_api_key"]:
        return True
    elif not admin and key == config["api_key"]:
        return True
    else:
        return False


def GetConfig():
    global CONFIG
    try:
        with open("controller-config.json", "r") as config_file:
            CONFIG = json.load(config_file)
        return CONFIG
    except:
        # There's on existing config, populate it and return, or fail it out.
        GetControllerDomain()
        return CONFIG


def SaveConfig():
    global CONFIG
    with open("controller-config.json", "w") as config_file:
        json.dump(CONFIG, config_file)