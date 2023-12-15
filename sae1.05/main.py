from scapy.all import *

common = [80, 443, 67, 68, 20, 21, 23, 22, 53, 8080, 123, 25, 3389, 110, 554, 445, 587, 993, 137, 139, 8008, 500, 143, 161, 162, 389, 1434, 5900] 
# liste des 28 ports les plus utilisés
"""p=input("ip : ")
for i in range(len(common)):
    x=common[i]
    paquet = IP(dst=p) / TCP(dport=x, flags='S')
    send(paquet)
    # envoi une trame a tout les ports de la liste common 
   """


try : 
    def main(arg, ip) :
        if arg == "-a":
            # début du programme
            try :    
                ip=input(f"entrez les 3 premiers octets de votre ip (x.x.x):\n ")
                for i in range(256):   # envoi un paquet a tout les hotes entre 0 et 255
                    x=ip+f".{i}"       # ajoute la valeur de l'itération actuelle a la fin de l'ip
                    paquet = IP(dst=x) / ICMP() # assemble le paquet
                    print(x)           #print l'ip de l'itération actuelle
                    send(paquet)                    
                    reply = sr1(paquet, timeout=3)    #store la réponse du ping de l'itération actuelle et met un timeout de 3
                if not (reply is None):               #check si la réponse est positive et print en conséquense
                    print(x, "is online")
                else:
                    print("Timeout waiting for %s" % paquet[IP].dst) 
            except KeyboardInterrupt :                
                print(f"Ctrl + C pressed [·]\n Exiting...")
            except traceback :
                print("Veuillez entrer une addresse ip sous le format x.x.x")
            # fin du programme 
    main()
except KeyboardInterrupt :
                print(f"Ctrl + C pressed [·]\n Exiting...")





# rep,non_rep = srp(paquet, timeout=0.5 )
# for element in rep : # element représente un couple (paquet émis, paquet reçu)
# 	if element[1][ICMP].type == 0 : # 0 <=> echo-reply voir page de Wikipedia
# 		print( element[0][IP].dst + ' a renvoye un echo-reply ')
# for element in non_rep : # element représente un couple (paquet émis, paquet reçu)
# 	if element[1][ICMP].type == 8 : # 8 <=> echo-request voir page de Wikipedia
# 		print( element[0][IP].dst + ' : aucun echo-reply ')
