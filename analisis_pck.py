import sys
import pyshark
#import scapy.all as scapy
from mac_vendor_lookup import MacLookup
mac = MacLookup()

def main():
    #"/home/c0t0rrr0/Documents/investigacion/dataset/captures_IoT-Sentinel/Aria/Setup-A-5-STA.pcap"
    path = sys.argv[1]
    
    capture = pyshark.FileCapture(path)
    #va a guardar los paquetes:
    #ip src, ip dst y sus respectivos port
    conversations = []
    for packet in capture:
        results = network_conversation(packet)
        if results is not None:
            conversations.append(results)
    print("CONVERSACION")
    print("============")
    for item in conversations: print(item)
    print("============\n")

    #pasas el pcap para analizarlo
    net = net_analisis(path)

    for dis in net:
        print(dis)

    target_ip = input("Ingresa el ip del dispositvo: ")
    mac_address = get_mac(path, target_ip)
    if mac_address:
        print(f"La dirección MAC correspondiente a la IP {target_ip} es: {mac_address}")
    else:
        print(f"No se encontró la dirección MAC para la IP {target_ip}")

    find_vendor(mac_address)

    

def network_conversation(packet):    
  try:
    protocol = packet.transport_layer
    source_address = packet.ip.src
    source_port = packet[packet.transport_layer].srcport
    destination_address = packet.ip.dst
    destination_port = packet[packet.transport_layer].dstport
    info_p = (f'{protocol} {source_address}:{source_port} --> {destination_address}:{destination_port}')
    return info_p
  
  except AttributeError as e:
    pass
  
def get_mac(pcap_file, target_ip):
    cap = pyshark.FileCapture(pcap_file, display_filter=f"ip.src == {target_ip}")

    for packet in cap:
        if "ip" in packet:
            if "eth" in packet:
                return packet.eth.src        
                
    return "no mac"

def net_analisis(path):
    #path = "/home/c0t0rrr0/Documents/investigacion/dataset/captures_IoT-Sentinel/Aria/Setup-A-5-STA.pcap"
    capture = pyshark.FileCapture(path)
    dev = []
    ips = []
    for pkt in capture:
        try:
            #para tener de forma unica un ip: [n][0]
            ip_s = pkt.ip.src
            ip_d = pkt.ip.dst
            if ip_s not in ips:
                ips.append(ip_s)
            if ip_d not in ips:
                ips.append(ip_d)
            
            #asociar los puertos al ip: [n][1]
            port_s = pkt[pkt.transport_layer].srcport
            port_d = pkt[pkt.transport_layer].dstport

            ip_s_index = None
            ip_d_index = None  
            #para poder seguir el ip
            #segun el port que se encuentra matchas con el ip en dev
            #buscas el indice dentro de dev
            for i, item in enumerate(dev):
                if item[0] == ip_s:
                    ip_s_index = i
                if item[0] == ip_d:
                    ip_d_index = i
            
            if ip_s_index is not None:
                #si no esta el puerto 
                if port_s not in dev[ip_s_index][1]:
                    dev[ip_s_index][1].append(port_s)
            else:
                dev.append([ip_s, [port_s]])
            
            if ip_d_index is not None:
                #si no esta el puerto
                if port_d not in dev[ip_d_index][1]:
                    dev[ip_d_index][1].append(port_d)
            else:
                dev.append([ip_d, [port_d]])

        except AttributeError as e:
            pass
    return dev
    #print("info: ", dev)

def find_vendor(mac_addr):  
    byte = mac_addr.split(":")
    print("mac descompuesto: ", byte)

    #https://www.mist.com/get-to-know-mac-address-randomization-in-2020/
    if byte[0][1] != '2' and byte[0][1] != '6' and byte[0][1] != 'a' and byte[0][1] !=  'e': 
        try:
            print("El vendor del dispositivo es:")
            print(f"--->:{mac.lookup(mac_addr)}\n" )
        except:
            print("ERROR: mac_vendor_lookup.VendorNotFoundError")
            print("puede ser que el mac addres no este registrado en la base de datos")
    else:
        print(f"el {mac_addr} posiblemente usa mac randomization")
        print("es posible que sea un celular, tableta o computadora personal")
        print("o su OS sea IOS, Android o Windows")

    

if __name__ == "__main__":
    main()