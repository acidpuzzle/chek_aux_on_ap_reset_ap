import logging
from itertools import repeat

from lab_tfsm import *
from tool_ssh import *
from tool_db_sch import *


logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(name)s - %(funcName)s() - %(message)s',
    level=logging.INFO
)
logging.getLogger("tool_ssh").setLevel(logging.INFO)
logging.getLogger("paramiko").setLevel(logging.INFO)
logger = logging.getLogger(__name__)


def netmiko_ap(network: str, creds_env_var: str) -> list:
    try:
        return [
            cisco_ios_ssh(str(ip), creds_env_var)
            for ip
            in ip_network(network)
            if ip_network(network)[30] < ip < ip_network(network)[255]
        ]
    except ValueError as error:
        logging.error(error)


def check_aux_on_ap(sch_mgmt_net: str, creds_env_var: str):
    check_command = "sho ip int br | i GigabitEthernet1"
    ap_with_disabled_intf = []
    probable_ap = netmiko_ap(sch_mgmt_net, creds_env_var)

    output_results = run_in_threads(get_config, probable_ap, repeat(check_command))

    tmpl = "lab_tfsm/templates/sh_ip_int_br.tfsm"
    for ap, result in zip(probable_ap, output_results):
        if result:
            result = parse_output_to_dict(tmpl, result)[0]
            if result['STATUS'] == 'administratively down':
                logger.info(f"AP with disabled port: {ap['host']}")
                ap_with_disabled_intf.append(ap)

    return ap_with_disabled_intf


def enable_aux_on_ap(ap_with_disabled_aux: list) -> None:
    enable_command = (
        'debug capwap console cli\n'
        'configure terminal\n'
        'interface GigabitEthernet1\n'
        'no shut\n'
        'end\n'
        'wr\n'
    )
    if ap_with_disabled_aux:
        for ap in ap_with_disabled_aux:
            logger.info(f"Enable AUX on {ap['host']}")
        run_in_threads(get_config, ap_with_disabled_aux, repeat(enable_command))
    else:
        logger.info(f"Not found AP with disabled AUX.")


def write_erase_all_ap(sch_mgmt_net: str, creds_env_var: str) -> None:
    write_erase_command = (
        'capwap ap erase all\n'
        'debug capwap console cli\n'
        'delete /force /recur *config*\n'
        'delete /force /recur *cfg*\n'
        'delete /force /recur *capwap*\n'
        'delete /force /recur *-fs\n'
        'reload\n'
        'no\n'
        '\n'
    )
    probable_ap = netmiko_ap(sch_mgmt_net, creds_env_var)

    if probable_ap:
        run_in_threads(get_config, probable_ap, repeat(write_erase_command))


if __name__ == "__main__":

    creds = "CISCO_AP_CREDS"
    sch_subnet = "10.171.252.0/23"
    # print(check_aux_on_ap(sch_subnet, creds))
    # enable_aux_on_ap(check_aux_on_ap(sch_subnet, creds))
    # write_erase_all_ap(sch_subnet, creds)

    # wlc11_sch = old_db_session.query(OldSchool).filter_by(vwlc='vWLC-11').all()
    wlc08_sch = old_db_session.query(OldSchool).filter_by(vwlc='vWLC-8', ).all()
    wlc18_sch = old_db_session.query(OldSchool).filter_by(vwlc='vWLC-18').all()

    wlc08_sch_and_wlc18_sch = wlc08_sch + wlc18_sch

    print(wlc08_sch_and_wlc18_sch)

    # for sch in wlc18_sch:
    #     print(sch.school, sch.net_pak)

    for _ in range(3):
        for sch in wlc08_sch_and_wlc18_sch:

            logger.info(f"Clear AP condig in {sch.school}, network {sch.net_pak} ")
            write_erase_all_ap(sch.net_pak, creds)
