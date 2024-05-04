import sys
from collections import defaultdict
import pyshark
#import scapy.all as scapy
from mac_vendor_lookup import MacLookup
mac = MacLookup()

def main():
    #path = "/home/c0t0rrr0/Documents/investigacion/dataset/captures_IoT-Sentinel/Aria/Setup-A-5-STA.pcap"
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
    net = pcap_analisis(path)
    
    #desplegas la informacion
    net_analisis(net)

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
  
def pcap_analisis(path):
    #path = "/home/c0t0rrr0/Documents/investigacion/dataset/captures_IoT-Sentinel/Aria/Setup-A-5-STA.pcap"
    capture = pyshark.FileCapture(path)
    dev = defaultdict(list)
    #dev = []
    ips = []
    for pkt in capture:
        try:
            #busca el ip destino que hay en el paquete
            ip_s = pkt.ip.src
            #para poder buscar los mac addres por ip
            if ip_s not in ips:
                #verifica si el paquete tiene un campo ethernet
                if "eth" in pkt:
                    mac = pkt.eth.src
                ips.append(ip_s)
            
            #busca el puerto destino que hay en el paquete
            port_s = pkt[pkt.transport_layer].srcport
            port_d = pkt[pkt.transport_layer].dstport

            #si es un diccionario no necesito buscar el indice usando un for
            l_dest = []
            if ip_s in dev:
                #si no esta el puerto
                # print("port",port_d)
                # print(f"ip:{ip_s}, puerto:{dev[ip_s][1]}")
                if port_d not in dev[ip_s][1]:
                    #append el port al ip correspondiente
                    dev[ip_s][1].append(port_d)

            else:
                l_dest.append(port_d)
                dev[ip_s] = [mac, l_dest]

        except AttributeError as e:
            pass
    #print("info: ", dev)
    return dev

def net_analisis(net):

    info = []
    for ip,flow in net.items():
        encontrado, vendor = find_vendor(flow[0])
        if encontrado:
            info.append((ip,flow[0],vendor,flow[1]))

    print("\n<<<INFORMACIO>>>")
    for dev in info:
        print(f"IP:{dev[0]}, MAC:{dev[1]}, {dev[2]}")
        print("puertos a los que se conecto:", dev[3],"\n")


def find_vendor(mac_addr):  
    #print(mac_addr)
    byte = mac_addr.split(":")
    #print("mac descompuesto: ", byte)

    #https://www.mist.com/get-to-know-mac-address-randomization-in-2020/
    if byte[0][1] != '2' and byte[0][1] != '6' and byte[0][1] != 'a' and byte[0][1] !=  'e': 
        try:
            #print("El vendor del dispositivo es:")
            vendor = mac.lookup(mac_addr)
            #print(f"--->:{vendor}\n" )
            return True, vendor
        except:
            print("ERROR: mac_vendor_lookup.VendorNotFoundError")
            print("puede ser que el mac addres no este registrado en la base de datos")
            #para darle update y ver si se logra conseguir el vendor
            mac.update_vendors()    
            print("puede volver a cargar el programa...")
    else:   
        print(f"el {mac_addr} posiblemente usa mac randomization")
        print("es posible que sea un celular, tableta o computadora personal")
        print("o su OS sea IOS, Android o Windows")

    

if __name__ == "__main__":
    main()