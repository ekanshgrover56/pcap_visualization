#Name = Ekansh Grover (ekansh.grover@colorado.edu)
#Purpose = PCAP parser and more
#Date = 10/24/2016
#Subject = Large Scale Networks

import dpkt,GeoIP,socket
from prettytable import PrettyTable
from collections import Counter
import gmplot
import re

#getting Lat long from GeoIP database
def Get_Lat_Long(list):
    gi = GeoIP.open('GeoLiteCity.dat',GeoIP.GEOIP_STANDARD)
    Lat,Long = [], []
    for value in list:
        gir =gi.record_by_addr(value)
        if gir:
            Lat.append(gir['latitude'])
            Long.append(gir['longitude'])
    Google_Plotter(Lat,Long)

#Plotting on Google Maps and saving html
def Google_Plotter(Lat,Long):
    gmap = gmplot.GoogleMapPlotter(39.73915, -104.9847, 16)
    gmap.heatmap(Lat,Long)
    gmap.draw("pcap_reader.html")

#Getting Country details for IPs
def Get_Country(list,heading):
    gi = GeoIP.open('GeoLiteCity.dat',GeoIP.GEOIP_STANDARD)
    Country_List = []
    for value in list:
        gir = gi.record_by_addr(value)
        if gir:
            Country_List.append(gir['country_name'])
    Country_List_Sorted=Country_List_sorted(Country_List)
    ptables(Country_List_Sorted,heading)

def Country_List_sorted(Country_List):
    return Counter(Country_List).most_common()

#Printing Tables
def ptables(list, heading):
    table = PrettyTable([heading,"Occurance"])
    for value in list:
        table.add_row([value[0],value[1]])
    print(table)

#TOP IPs
def Top_10_ips(SRC_IP, DES_IP):
    Top_10_src = Counter(SRC_IP).most_common()[:10]
    Top_10_des = Counter(DES_IP).most_common()[:10]
    ptables(Top_10_src,"IP_SRC")
    ptables(Top_10_des,"IP_DES")

#Removing Private IPs(My own in this case)
def Remove_Private_Ips(IP_LIST):
    IP = []
    for IP_add in IP_LIST:
        if re.match(r"^(?:10|127|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\..*",IP_add) == None:
            IP.append(IP_add)
    return IP

#Reading the PCAP file
def Pcap_Parser():
    SRC_IP, DES_IP = [],[]
    file = open('test_data.pcap','rb')
    pcapreader = dpkt.pcap.Reader(file)
    for extra, data in pcapreader:
        ether = dpkt.ethernet.Ethernet(data)
        if ether.type == dpkt.ethernet.ETH_TYPE_IP:
            ip = ether.data
            try:
                src = socket.inet_ntoa(ip.src)
                dst = socket.inet_ntoa(ip.dst)
                SRC_IP.append(src)
                DES_IP.append(dst)
            except AttributeError:
                pass
    SRC_IP = Remove_Private_Ips(SRC_IP)
    DES_IP = Remove_Private_Ips(DES_IP)
    return SRC_IP, DES_IP

#Main function
def main():
    SRC_IP, DES_IP = Pcap_Parser()
    Top_10_ips(SRC_IP, DES_IP)
    Get_Country(SRC_IP,"SRC_COUNTRY")
    Get_Country(DES_IP,"DES_COUNTRY")
    Get_Lat_Long(SRC_IP)

if __name__=="__main__":
	main()
