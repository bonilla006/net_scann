#version 2 de scan para conseguir MAC addr
import ipaddress
from alive_progress import alive_bar
import scapy.all as scapy
from mac_vendor_lookup import MacLookup
#from scapy.all import IP, TCP, ICMP, srp1, Ether, sr, sr1

def main():
    src_ip = input("Ingrese un Ip: ")
    ips = hard_scanner(src_ip)

    #print(ips)
    find_mac(ips)


    print("F.D.P")

def hard_scanner(src_ip):
    network = ipaddress.ip_network(src_ip)
    print(f"Haciendo scaning del network <{network}>")

    #el timpo de la barra de progreso depende de el netmask
    #/24 = 244
    with alive_bar(254) as progreso:
        ips_actv = []
        for grb in network:
            # Ignore e.g. xxx.xxx.xxx.0 and xxx.xxx.xxx.255
            if grb == network.broadcast_address or grb == network.network_address: continue

            #se crea el paquete para saber si el device esta activo2
            ip = str(grb)
            pkt = scapy.Ether()/scapy.IP(dst = ip)/scapy.ICMP()
            res = scapy.srp1(pkt, timeout = 3, verbose = False)

            if res: ips_actv.append(ip)
                # mac_addr = scapy.getmacbyip(ip)
                # print(f"{ip, mac_addr}: esta activo")
               
            progreso()
    return ips_actv

def find_mac(ips):
    all_mac = []
    for ip in ips:
        mac = scapy.getmacbyip(ip)
        print(f"{ip, mac}")
        all_mac.append(mac)

    #print(all_mac)

    #lst_byte es una lista de lista
    lst_byte = []
    for mac in all_mac:
        #i es un str, de len = 17 
        list_i = mac.split(":")
        lst_byte.append(list_i)

    print("mac descompuesto: ", lst_byte)

    ind = 0
    rand_mac = {}
    #cada byte va ser la lista de los byte del mac de cada mac addr
    for i,byte in enumerate(lst_byte):
        #i es un str
        print("mac addr: ", all_mac[i])
        #mac addres que son fijos
        #i[0][i] es el segundo caracter del primer byte
        if byte[0][1] != '2' and byte[0][1] != '6' and byte[0][1] != 'a' and byte[0][1] !=  'e': #https://www.mist.com/get-to-know-mac-address-randomization-in-2020/
            print("bueno")
            find_vendor(all_mac[i])
            
        else:
            #crear un diccionario con el mac addres y un str "random"
            #dic = {mac:"rand"}
            print("mac posiblemente random")
            rand_mac[all_mac[i]] = "rand"
        ind+=1
    print("mac random: ", rand_mac)

def find_vendor(mac_address):
    #tengo un error aqui, no esta funcionado la funcion
    try:
        print("LOOKUP: ", MacLookup.lookup(mac_address))
    except:
        print("ERROR: mac_vendor_lookup.VendorNotFoundError")


if __name__ == "__main__":
    main()