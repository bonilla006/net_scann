import sys
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
    net = net_analisis(path)
    info = []
    for dis in net:
        #print(dis)
        encontrado, vendor = find_vendor(dis[1])
        if encontrado:
            info.append((dis[0],dis[1],vendor,dis[2]))
    
    for dis in info:
        print(dis)

    

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
  
def net_analisis(path):
    #path = "/home/c0t0rrr0/Documents/investigacion/dataset/captures_IoT-Sentinel/Aria/Setup-A-5-STA.pcap"
    capture = pyshark.FileCapture(path)
    dev = []
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
            port_d = pkt[pkt.transport_layer].dstport

            #para poder seguir el ip
            ip_s_index = None  
            
            #segun el port que se encuentra matchas con el ip en dev
            #buscas el indice dentro de dev
            #si el index es none, eso implica que no se pudo
            #parear el ip que se esta viendo con un ip en la lista
            for i, ip in enumerate(dev):
                #si el ip en dev matchea con el ip del paquete que se esta viendo
                if ip[0] == ip_s:
                    ip_s_index = i
            
            if ip_s_index is not None:
                #si no esta el puerto 
                if port_d not in dev[ip_s_index][2]:                        
                    dev[ip_s_index][2].append(port_d)   
            #index = none
            else:
                dev.append([ip_s, mac, [port_d]])

        except AttributeError as e:
            pass
    #print("info: ", dev)
    return dev
    

def find_vendor(mac_addr):  
    #print(mac_addr)
    byte = mac_addr.split(":")
    print("mac descompuesto: ", byte)

    #https://www.mist.com/get-to-know-mac-address-randomization-in-2020/
    if byte[0][1] != '2' and byte[0][1] != '6' and byte[0][1] != 'a' and byte[0][1] !=  'e': 
        try:
            print("El vendor del dispositivo es:")
            vendor = mac.lookup(mac_addr)
            print(f"--->:{vendor}\n" )
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