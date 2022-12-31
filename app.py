import io
import os
from flask import Flask, request
from flask import send_file, render_template, render_template_string
from pathlib import Path
import subprocess
import logging
import json

app = Flask(__name__)


## Controller -
@app.route('/create/<domain>')
def CreateCluster(domain, public_key=None, managed_credentials=False):
    ''' Initial call to create a cluster.
        This spins up an instances with:
        - headscale
        - headscale config
        - headscale service setup
        - k3s master setup
        - k3s proxy setup

        If user chooses the option to manage credentials, secrets for headscale are stored.

    '''
    return render_template('master-launch.sh',
      controller_domain=domain)


@app.route('/connect/interactive/<cluster>')
def InteractiveConnectNode(cluster):
    ''' Starts up a new node and allows them to not provide arguments.
        Requires interactive configuration by the admin.
    '''
    pass

@app.route('/connect/worker/<key>')
def ConnectNode(key):
    ''' When a new node is started up, it's cloud-init calls this endpoint.
        Returns a full configuration script that is intended to be executed.
        This is expected to be an automated endpoint.
        There is another endpoint that is interactive, or allows the admin to configure via controller UI.
    '''
    
    #TODO: Verify key
    if key and key != "a":
        raise Exception("Bad authorization")

    # Currently static, used in the TN namespace.
    cluster = "k8s"

    # Use headscale to generate a pre-auth key for this node. Make it 1 time use, and set tags.
    # Currently default tags, everything is "worker".
    args = request.args.to_dict()
    
    # We should check that the hostname is not taken
    # args.get("hostname")

    tags = []
    additional_tailscale_args = []

    #TODO: We need tag validation once we use them for something
    #TODO: We need to do validation on clustername and key
    if 'environment' in args:
        tags.append(args["environment"])

    if 'region' in args:
        tags.append(args["region"])

    if 'exit' in args and args["exit"]:
        tags.append("egress")
        # TODO: Validate that the exit node is one we actually want to route outbound through
        additional_tailscale_args.append("--advertise-exit-node")
    
    # Cluster members advertise the routes
    cluster_cidrs = "10.42.0.0/16,10.43.0.0/16"
    additional_tailscale_args.append('--advertise-routes "%s" --accept-routes' %  cluster_cidrs)

    #TODO: something to support egress outbound
    #--exit-node to be set if we want to route outbound traffic out of an outbound proxy.
    #TODO: something to support advertising routes automatically for things like AWS SES.
    # --advertise-routes

    # For now there are some defaults:
    controller_domain = GetControllerDomain()

    controller_private_ip = GetControllerIP()
    tailscale_preauth_key = GeneratePreauthKey(namespace=cluster, tags=tags)

    with open("/data/k3s/server/agent-token", "r") as agent_token_file:
        k3s_token = agent_token_file.read().strip()


    additional_tailscale_args = " ".join(additional_tailscale_args)
    ##On the k8s api need to label node-role.kubernetes.io/worker=worker - nodes cant select it for themselves
    return render_template('worker-launch.sh',
      controller_domain=controller_domain,
      controller_private_ip=controller_private_ip,
      tailscale_preauth_key=tailscale_preauth_key,
      k3s_install_token=k3s_token,
      tailscale_args=additional_tailscale_args)


def GeneratePreauthKey(namespace=None, api=None, key=None, tags=[]):
    #headscale_path = "./binaries/headscale_0.17.0_linux_amd64"
    headscale_path = "headscale"
    command = [headscale_path, "authkey", "create","-o", "json" , "-n", namespace]

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
        key_command = subprocess.run(command, stdout=subprocess.PIPE, text=True, check=True, env=env)
    # Creation failed
    except Exception as e:
        raise(e)
        #raise(Exception("Unable to generate preauth key"))
    if key_command.returncode:
        logging.warn(" ".join(command))
        logging.warn("env: %s" % env)
        raise(Exception("Unable to generate preauth key"))
    result = json.loads(key_command.stdout)
    if "error" in result:
        raise(Exception("Unable to generate preauth key: %s" % result["error"]))
    
    return result["key"]


@app.route('/applications/headscale/<architecture>')
def get_headscale_binary(architecture, version="0.17.0"):
    #filename = 'uploads\\123.jpg'
    with open("binaries/headscale_%s_linux_%s" % (version, architecture), "rb") as f:
        return send_file(io.BytesIO(f.read()), mimetype='application/octet-stream')


@app.route('/config/headscale/<key>')
def get_headscale_config(key):
    return render_template('headscale_config.yaml', name=key)

@app.route('/config/kubernetes/<key>')
def get_kubernetes_config(key):
    '''Returns the local kubectl configuration.
       Expected to be run after initializing the cluster with a 1-time code.
    '''
    if not AuthenticateOneTimeConfigKey(key):
        return {"error": "unauthenticated"}

    controller_private_address = "%s:6443" % GetControllerIP()
    with open("/etc/rancher/k3s/k3s.yaml", "r") as ctl_file:
        kubectl_file = ctl_file.read()
    kubectl_file.replace(controller_private_address, "%s:6445" % GetControllerDomain())
    return kubectl_file

def GetControllerDomain():
    # For now there are some defaults:
    controller_domain = os.environ.get("K8SD_CONTROLLER_DOMAIN")
    if not controller_domain:
        logging.error("Need to provide a K8SD_CONTROLLER_DOMAIN environment variable")
    return controller_domain

def GetControllerIP():
    return "100.64.0.1"

def AuthenticateOneTimeConfigKey(key):
    '''Returns true if this is the first call to fetch the config file.'''
    if os.path.exists("configuration_accessed"):
        return False
    else:
        Path("configuration_accessed").touch()
        return True
