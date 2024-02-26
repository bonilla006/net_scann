from scapy.all import *
from mac_vendor_lookup import MacLookup
import re

mac = MacLookup()
def main():
    #patron para reconocer ipv4 addr
    #si el ip que se envia matchea con esta expresion, es valido
    ip_add_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]*$")#regular expresion

    #captura el addr para el ARP, scann el network segun 
    #el ip que pongas
    while True:
        ip_add_pattern_entrado = input("\nEntre el ip addr y el rango: ")#192.168.1.1/24
        if ip_add_pattern.search(ip_add_pattern_entrado):
            print(f"{ip_add_pattern_entrado} es un ip valido")
            break

    #tabla ARP con el mac addr y el ip
    print("<<<Tabla ARP>>>")
    resultados, _ = arping(ip_add_pattern_entrado)

    #se va a mover por la tabla ARP y se va a guardar unicamente
    #los mac addr en la lista mac_list
    mac_list = []    
    for _,r in resultados:
        mac_list.append(r[Ether].src)

    #print(type(mac_list[0]), mac_list[0])
        
    #print(mac_list)
    #lst_byte es una lista de lista
    lst_byte = []
    for i in mac_list:
        #i es un str, de len = 17 
        list_i = i.split(":")
        lst_byte.append(list_i)

    #print(lst_byte)
    ind = 0
    rand_mac = {}
    #cada i va ser la lista de los byte del mac de cada mac addr
    for i in lst_byte:
        #i es un str
        print("mac addr: ", mac_list[ind])
        #mac addres que son fijos
        #i[0][i] es el segundo caracter del primer byte
        if i[0][1] != '2' and i[0][1] != '6' and i[0][1] != 'a' and i[0][1] !=  'e': #https://www.mist.com/get-to-know-mac-address-randomization-in-2020/
            find_vendor(mac_list[ind])
        else:
            #crear un diccionario con el mac addres y un str "random"
            #dic = {mac:"rand"}
            print("mac posiblemente random")
            rand_mac[mac_list[ind]] = "rand"
        ind+=1
    print("mac random: ", rand_mac)
    print("<<<FIN>>>")

def find_vendor(mac_address):
    try:
        print("LOOKUP: ",mac.lookup(mac_address))
    except:
        print("ERROR: mac_vendor_lookup.VendorNotFoundError")

if __name__ == "__main__":
    main()