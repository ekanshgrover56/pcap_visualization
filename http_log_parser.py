#Name = Ekansh Grover (ekansh.grover@colorado.edu)
#Purpose = HTTP log parser and more
#Date = 10/24/2016
#Subject = Large Scale Networks

from collections import Counter
from prettytable import PrettyTable
import matplotlib.pyplot as plt
import numpy as np
import gmplot
import GeoIP

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
    gmap.draw("Http_ip_location.html")

#getting top 10 User-Agents
def Top_10_User_Agent(User_Agent,heading):
    Top_10_User_Agent = Counter(User_Agent).most_common()[:10]
    ptables(Top_10_User_Agent, heading)

#drawing bar graph
def Draw_Graphs(Value,heading, heading_x,image_file):
    Y_Value, X_Value=[], []
    for each in Value:
        Y_Value.append(each[1])
        X_Value.append(each[0])
    y_p = np.arange(len(Y_Value))
    X_Value = [value.replace('http://www2.itt-tech.edu','..') for value in X_Value]
    width = 0.2
    plt.style.use('ggplot')
    plt.rcParams['font.size'] = 10
    plt.rcParams['xtick.labelsize'] = 7
    plt.barh(y_p, Y_Value, align = 'center', alpha = 0.5)
    plt.yticks(y_p,X_Value)
    plt.ylabel(heading_x)
    plt.xlabel("Hits")
    plt.title(heading)
    plt.savefig(image_file)
    plt.show()

#getting top 10 links
def Top_10(links):
    Top_10_links = Counter(links).most_common()[:10]
    pages = []
    for link in links:
        if "?" in link:
            pages.append(link.split("?")[0]+"\"")
        else:
            pages.append(link)
    Top_10_pages = Counter(pages).most_common()[:10]
    ptables(Top_10_links, "Links")
    ptables(Top_10_pages, "Pages")
    Draw_Graphs(Counter(links).most_common()[:25],"25 Most Common Links (.. --> \"http://www2.itt-tech.edu\")","Links","links.png")
    Draw_Graphs(Counter(pages).most_common()[:25],"25 Most Common Pages (.. --> \"http://www2.itt-tech.edu\")","Pages","Pages.png")

#Printing out tables
def ptables(list, heading):
    table = PrettyTable([heading,"Frequency"])
    for value in list:
        table.add_row([value[0],value[1]])
    print(table)

#parsing the logs
def log_parser():
    links, IP, User_Agent, User_Agent_heading = [], [], [], []
    file = open("itt-tech2-access_log","r")
    for line in file:
        try:
            IP.append(line.split(" ")[0])
            User_Agent_heading.append(line.split(" ")[11])
            User_Agent.append(line.split(" ")[11]+" "+line.split(" ")[12]+" "+line.split(" ")[13])
        except:
            pass
        if line.split(" ")[10] == "\"-\"":
            pass
        else:
            links.append(line.split(" ")[10])
    return links, IP, User_Agent, User_Agent_heading

#Main Function
def main():
    links, IP, User_Agent, User_Agent_heading = log_parser()
    Top_10(links)
    Top_10_User_Agent(User_Agent,"Top 10 User-Agents")
    Top_10_User_Agent(User_Agent_heading,"Top 10 User-Agents title")
    Get_Lat_Long(IP)

if __name__=="__main__":
	main()
