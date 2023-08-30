#!/usr/bin/env python3
# -*- coding: utf-8 -*-

VERSION = "0.1"

import os
import sys
import subprocess
import re
import time
import pathlib
import shutil
import json
import tomllib

with open("/etc/wireguard/conf.toml", "rb") as toml_conf:
    general_conf = tomllib.load(toml_conf)
    SETTINGS = general_conf["SETTINGS"]
    INTERFACES = general_conf["INTERFACES"]

def menu():
    while True:
        actions = [sys.exit, list_clients, add_client, remove_client, enable_client, disable_client, regenerate_server_conf, regenerate_client_conf, about]
        print()
        waiting = False
        for interface in INTERFACES:
            if pathlib.Path("/etc/wireguard/" + interface["name"] + ".tmp").exists():
                print("A job is waiting for client disconnection on " + interface["name"] + " (" + interface["location"] + ")")
                waiting += 1
        if not waiting:
            print("No jobs are waiting.")
        print()
        print("Wireguard utility")
        print("0 : Exit")
        print("1 : List all clients")
        print("2 : Add a client")
        print("3 : Remove a client")
        print("4 : Enable a client")
        print("5 : Disable a client")
        print("6 : Force regenerate server conf")
        print("7 : Force regenerate client conf")
        print("8 : About")
        try:
            action = int(input("Choose your action > "))
        except:
            print("Invalid input... Try again.")
        else:
            if action not in list(range(len(actions))):
                print("Invalid input... Try again.")
            else:
                print()
                actions[action]()

def list_clients():
    clients = load_clients()
    print(" IP On/Off Connected_to Client_name")
    print("-----------------------------------")
    [print(client["ip"].rjust(3), ("On" if client["state"] else "Off").rjust(6), is_connected(client["pubkey"]).rjust(12), client["name"]) for client in clients]

def add_client():
    clients = load_clients()
    name_is_ok = False
    while not name_is_ok:
        name_is_ok = True
        client_name = input("Client name ? > ")
        if client_name in [client["name"] for client in clients]:
            print("Client name already in use\nTry another one...")
            name_is_ok = False
        if not re.match("^[A-Za-z0-9_-]+$", client_name):
            print("Client name must match : a-z A-Z 0-9 _ - (no spaces)\nTry another one...")
            name_is_ok = False
    ip = SETTINGS["minIP"]
    while str(ip) in [client["ip"] for client in clients]:
        ip += 1
    if ip > 254 :
        print("Error : cannot add a client, all IPs are attributed.\nAborting...")
    else:
        privkey = wg_privkey()
        psk = wg_psk()
        clients.append({
            "ip" : str(ip),
            "name" : client_name,
            "state" : True,
            "privkey" : privkey,
            "pubkey" : wg_pubkey(privkey),
            "psk" : psk
            })
        save_clients(clients)
        regenerate_client_conf(UI = False)
        regenerate_server_conf(UI = False)
        print("Added", client_name, "\nConfiguration files is in /etc/wireguard/clients.d")

def remove_client():
    clients = load_clients()
    client_name = input("Client name ? > ")
    if not client_name in [client["name"] for client in clients]:
        print("Client do not exist. Aborting...")
    else:
        for interface in INTERFACES:
            os.remove("/etc/wireguard/clients.d/" + client_name + "." + interface["location"] + ".conf")
        save_clients([client for client in clients if client["name"]!=client_name])
        regenerate_server_conf(UI = False)
        print("Removed", client_name)

def enable_client():
    clients = load_clients()
    client_name = input("Client name ? > ")
    if not client_name in [client["name"] for client in clients]:
        print("Client do not exist. Aborting...")
    else:
        for client in clients:
            if client["name"] == client_name:
                client["state"] = True
        save_clients(clients)
        regenerate_server_conf(UI = False)
        print("Enabled", client_name)

def disable_client():
    clients = load_clients()
    client_name = input("Client name ? > ")
    if not client_name in [client["name"] for client in clients]:
        print("Client do not exist. Aborting...")
    else:
        for client in clients:
            if client["name"] == client_name:
                client["state"] = False
        save_clients(clients)
        regenerate_server_conf(UI = False)
        print("Disabled", client_name)

def about():
    print("Small utility for Wireguard management")
    print("Made by Jacques Ferrand")
    print("Version :", VERSION)

# Function not in UI

def load_clients():
    # format of clients' file : "ip client_name status privkey psk" 
    with open("/etc/wireguard/clients", "r") as clients_file:
        clients_raw = clients_file.read().split("\n")
        clients = []
        for line in clients_raw:
            if line:
                line_parsed = line.split(" ")
                clients.append({
                    "ip" : line_parsed[0],
                    "name" : line_parsed[1],
                    "state" : bool(int(line_parsed[2])),
                    "privkey" : line_parsed[3],
                    "pubkey" : wg_pubkey(line_parsed[3]),
                    "psk" : line_parsed[4]
                    })
        return clients

def save_clients(clients):
    with open("/etc/wireguard/clients", "w") as clients_file:
        clients_file.write("\n".join([" ".join([
            client["ip"],
            client["name"],
            "1" if client["state"] else "0",
            client["privkey"],
            client["psk"]
            ]) for client in clients]))

def is_connected(client_pubkey):
    json_parsed = json.loads(subprocess.run(["/usr/share/doc/wireguard-tools/examples/json/wg-json"], capture_output = True).stdout.decode("utf-8").strip())
    for interface in INTERFACES:
        if client_pubkey in json_parsed[interface["name"]]:
            if int(time.time()) - int(json_parsed[interface["name"]][client_pubkey]["latestHandshake"]) < SETTINGS["disconnection_time"] :
                return interface["location"]
    return "None"


def wg_privkey():
    return subprocess.run(["wg", "genkey"], capture_output = True).stdout.decode("utf-8").strip()

def wg_pubkey(privkey):
    return subprocess.run(["wg", "pubkey"], capture_output = True, input=privkey.encode("utf-8")).stdout.decode("utf-8").strip()

def wg_psk():
    return subprocess.run(["wg", "genkey"], capture_output = True).stdout.decode("utf-8").strip()

def get_server_pubkey(interface_name):
    with open("/etc/wireguard/" + interface_name + ".conf", "r") as conf_file:
        for line in conf_file.readlines():
            if line.startswith("PrivateKey"):
                return wg_pubkey(line.split("=")[1].strip() + "=")

def regenerate_server_conf(UI = True):
    clients = load_clients()
    for interface in INTERFACES:
        with open("/etc/wireguard/" + interface["name"] + ".conf", "r") as conf_file, open("/etc/wireguard/" + interface["name"] + ".tmp", "w") as tmp_file:
            tmp_file.write(conf_file.read().split("# AUTO BELOW")[0].strip() + "\n\n# AUTO BELOW\n\n")
            for client in clients:
                if client["state"]:
                    tmp_file.write("\n".join([
                        "[Peer]",
                        "# Name = " + client["name"],
                        "AllowedIPs = 10.0." + interface["number"] + "." + client["ip"] + "/32, fd10:0:" + interface["number"] + ":" + hex(int(client["ip"])).split("x")[-1] + "::1/128",
                        "PublicKey = " + wg_pubkey(client["privkey"]),
                        "PresharedKey = " + client["psk"],
                        "PersistentKeepalive = " + SETTINGS["PersistentKeepalive"],
                        ]))
                    tmp_file.write("\n\n")
        if UI:
            reload_server_conf(interface["name"])
        else:
            pre_daemon(reload_server_conf, interface["name"])
    print("Regenerated server conf")

def reload_server_conf(interface_name):
    subprocess.run(["service", "wg-quick@" + interface_name, "stop"])
    os.remove("/etc/wireguard/" + interface_name + ".conf")
    os.rename("/etc/wireguard/" + interface_name + ".tmp", "/etc/wireguard/" + interface_name + ".conf")
    subprocess.run(["service", "wg-quick@" + interface_name, "start"])
    if pathlib.Path("/etc/wireguard/" + interface_name + ".tmp").exists():
        os.remove("/etc/wireguard/" + interface_name + ".tmp")

def regenerate_client_conf(UI = True):
    clients = load_clients()
    shutil.rmtree("/etc/wireguard/clients.d")
    os.makedirs("/etc/wireguard/clients.d", exist_ok = True)
    for client in clients:
            for interface in INTERFACES:
                with open("/etc/wireguard/clients.d/" + client["name"] + "." + interface["location"] + ".conf", "w") as clients_file:
                    clients_file.write("\n".join([
                        "[Interface]",
                        "# Name = " + client["name"],
                        "PrivateKey = " + client["privkey"],
                        "Address = 10.0." + interface["number"] + "." + client["ip"] + "/32, fd10:0:" + interface["number"] + ":" + hex(int(client["ip"])).split("x")[-1] + "::1/128",
                        "DNS = " + SETTINGS["DNS"],
                        "",
                        "[Peer]",
                        "# Name = " + interface["location"] + "." + SETTINGS["Endpoint"] + ":" + interface["port"],
                        "PublicKey = " + get_server_pubkey(interface["name"]),
                        "PresharedKey = " + client["psk"],
                        "Endpoint = " + SETTINGS["Endpoint"] + ":" + interface["port"],
                        "AllowedIPs = " + SETTINGS["AllowedIPs"],
                        "PersistentKeepalive = " + SETTINGS["PersistentKeepalive"]
                        ]))
    print("Regenerated client conf")

def pre_daemon(reload_server_conf, interface_name):
    lock_file = pathlib.Path("/etc/wireguard/" + interface_name + ".tmp")
    if lock_file.exists():
        lock_file.touch()
        return
    else:
        lock_file.touch()
        daemonize(wait_for, [interface_name, reload_server_conf, [interface_name]])

def daemonize(function, args):
    # Deamonize class. UNIX double fork mechanism.
    pid = os.fork() # do first fork
    if pid > 0:
        return # exit first parent
    os.chdir('/') # decouple from parent environment
    os.setsid() # decouple from parent environment
    os.umask(0) # decouple from parent environment
    pid = os.fork() # do second fork
    if pid > 0:
        sys.exit(0) # exit from second parent
    function(*args) # do the work
    sys.exit(0) # exit when work is done

def wait_for(interface_name, function, args):
    clients = load_clients()
    connected = 1
    while connected != 0:
        connected = 0
        json_parsed = json.loads(subprocess.run(["/usr/share/doc/wireguard-tools/examples/json/wg-json"], capture_output = True).stdout.decode("utf-8").strip())
        for client_pubkey in json_parsed[interface_name]:
            if client_pubkey in [client["pubkey"] for client in clients]:
                if int(time.time()) - int(json_parsed[interface_name][client_pubkey]["latestHandshake"]) < SETTINGS["disconnection_time"] :
                    connected += 1
    function(*args)

if __name__ == "__main__":
    if os.geteuid() != 0:
        exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")
    else:
        os.makedirs("/etc/wireguard/clients.d", exist_ok = True)
        pathlib.Path("/etc/wireguard/clients").touch()
        for interface in INTERFACES:
            pathlib.Path("/etc/wireguard/" + interface["name"] + ".conf").touch()
        menu()
