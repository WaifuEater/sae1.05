from scapy.all import *
import argparse
import signal
import ipaddress
import time


common = [80, 443, 67, 68, 20, 21, 23, 22, 53, 8080, 123, 25, 3389, 110, 554, 445, 587, 993, 137, 139, 8008, 500, 143, 161, 162, 389, 1434, 5900] 
# liste des 28 ports les plus utilisés
"""p=input("ip : ")
for i in range(len(common)):
    x=common[i]
    paquet = IP(dst=p) / TCP(dport=x, flags='S')
    send(paquet)
    # envoi une trame a tout les ports de la liste common 
   """
ip_valides = list()
# Fonction pour gérer le signal d'interruption (Ctrl + C)
def signal_handler(sig, frame):
    print("\nCtrl + C pressed [·]\nExiting...")
    sys.exit(0)
classe=0


# Fonction pour vérifier une plage d'adresses IP
def check_mult_ip(ip):
    try:
        if "/" in ip:
            ip, subnet = ip.split("/")
            subnet = int(subnet)
            network = ipaddress.ip_network(ip + '/' + str(subnet), strict=False)

            for subnet_ip in network.subnets(new_prefix=subnet):
                for ip in subnet_ip.hosts():
                    paquet = IP(dst=str(ip)) / ICMP()
                    print("Scan de ", ip)
                    send(paquet)
                    reply = sr1(paquet, timeout=3)
                    if reply is not None:
                        ip_valides.append(str(ip))
                        print(f"[✓] {ip} est ONLINE [✓]")
                    else:
                        print("[X] %s n'est pas joignable pour le moment [X]" % str(ip))
        else:
            # Reste du code pour la vérification d'une seule adresse IP
            check_ip(ip)
    except Exception as e:
        print("[?] Une erreur est survenue: [?] \n Vérifiez que le format de l'adresse IP est correct.\n", e)


# Fonction pour vérifier une seule adresse IP
def check_ip(ip):
    try:
        paquet = IP(dst=ip) / ICMP()
        print("scan de ", ip)
        send(paquet)
        reply = sr1(paquet, timeout=3)
        if reply is not None:
            print(f"[✓] {ip} est ONLINE [✓]")
        else:
            print("[X] %s n'est pas joignable pour le moment [X]" % paquet[IP].dst)
    except Exception as e:
        print("[?] Une erreur est survenue: [?]", e)


''' beugé et pas nécéssaire
    def port_check(ip):
    ports_valides = list()
    try:
        for i in common :
            x = common
            packet = IP(dst=ip) / TCP(dport=x, flags="S")
            send(packet)
            print("scan du port ", i)
            reply = sr1(packet, timeout=3)
            if reply is not None:
                ports_valides.append(i)
                print(f"[✓] port {i} est ONLINE [✓]")
            else:
                print("[X] Le port %s n'est pas joignable pour le moment [X]" % i)
    except Exception as e:
        print("[?] Une erreur est survenue: [?] \n ", e)
'''

# pour le truc arp
def arp_check(ip): 
    ip_found = False  # Indique si l'IP a été trouvée

    def arp_display(pkt):
        nonlocal ip_found
        if ARP in pkt and pkt[ARP].op == 2 and pkt[ARP].psrc == ip:
            print(f"ARP from: {pkt[ARP].psrc} to {pkt[ARP].pdst}")
            print(f"{ip} est bien présente dans le trafic ARP.")
            mac_address = pkt[ARP].hwsrc  # Récupère l'adresse MAC
            print(f"Adresse MAC de {ip}: {mac_address}")
            ip_found = True
            sys.exit(0)

    try:
        print("Écoute du trafic ARP...")
        duration = int(input("Entrez la durée d'écoute en secondes : "))
        start_time = time.time()
        while time.time() - start_time < duration:
            # Envoie une requête ARP spécifique pour obtenir la réponse contenant l'adresse MAC
            ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, verbose=False)
            for _, pkt in ans:
                arp_display(pkt)
            time.sleep(1)  # Attente avant de réessayer la requête ARP

        # Si l'IP n'est pas trouvée pendant la durée spécifiée
        if not ip_found:
            print(f"Aucune activité ARP pour l'adresse IP {ip} détectée pendant {duration} secondes.")
    except Exception as e:
        print("[?] Une erreur est survenue lors de l'écoute ARP: [?]", e)


    
    
    

# Fonction principale
def main():
    # Définition des arguments en utilisant argparse
    parser = argparse.ArgumentParser(description='Scan IP addresses.')
    parser.add_argument('ip', type=str, help='Adresse IP à vérifier')
    parser.add_argument('-t', action='store_true', help='Exécute la vérification pour toutes les adresses IP')
    parser.add_argument('-a', action='store_true', help='Execute la vérification pour une seule adresse IP')
    parser.add_argument('-l', action='store_true', help='Liste les addresse ip ayant répondu')
    # parser.add_argument('-po', action='store_true', help='Execute la vérification des 25 ports les plus communs')
    parser.add_argument('-p', action='store_true', help=f"Ecoute le traffic ARP et renvoi si l'ip est présente dans le traffic. | Si l'ip y figure, affiche l'addresse MAC correspondante") 
    parser.add_argument('-x', action='store_true', help='Exporter les résultats dans un fichier')
    parser.add_argument('-o', '--output_file', type=str, help='Nom du fichier de sortie')


    # Analyse des arguments de la ligne de commande
    args = parser.parse_args()
    ip_to_check = args.ip

    # Gestion du signal d'interruption (Ctrl + C)
    signal.signal(signal.SIGINT, signal_handler)

    
    # Choix du mode de vérification en fonction des arguments
    if args.t:
        check_mult_ip(ip_to_check)
    elif args.p:
        arp_check(ip_to_check)
    elif args.a:
        check_ip(ip_to_check)
    elif args.l:
        print(ip_valides)
    # elif args.po:
        # port_check(ip_to_check)
    else:
        print(f"Adresse IP à vérifier : {ip_to_check}")
    

# Point d'entrée du script
if __name__ == "__main__":
    main()





# rep,non_rep = srp(paquet, timeout=0.5 )
# for element in rep : # element représente un couple (paquet émis, paquet reçu)
# 	if element[1][ICMP].type == 0 : # 0 <=> echo-reply voir page de Wikipedia
# 		print( element[0][IP].dst + ' a renvoye un echo-reply ')
# for element in non_rep : # element représente un couple (paquet émis, paquet reçu)
# 	if element[1][ICMP].type == 8 : # 8 <=> echo-request voir page de Wikipedia
# 		print( element[0][IP].dst + ' : aucun echo-reply ')
                      
