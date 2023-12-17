from scapy.all import *
import argparse
import signal

# common = [80, 443, 67, 68, 20, 21, 23, 22, 53, 8080, 123, 25, 3389, 110, 554, 445, 587, 993, 137, 139, 8008, 500, 143, 161, 162, 389, 1434, 5900] 
# liste des 28 ports les plus utilisés
"""p=input("ip : ")
for i in range(len(common)):
    x=common[i]
    paquet = IP(dst=p) / TCP(dport=x, flags='S')
    send(paquet)
    # envoi une trame a tout les ports de la liste common 
   """

# Fonction pour gérer le signal d'interruption (Ctrl + C)
def signal_handler(sig, frame):
    print("\nCtrl + C pressed [·]\nExiting...")
    sys.exit(0)

# Fonction pour vérifier une plage d'adresses IP
def check_mult_ip(ip):
    try:
        for i in range(256):
            x = f"{ip}.{i}"
            paquet = IP(dst=x) / ICMP()
            print("scan de ", x)
            send(paquet)
            reply = sr1(paquet, timeout=3)
            if reply is not None:
                print(f"{x} est ONLINE")
            else:
                print("%s n'est pas joignable pour le moment" % paquet[IP].dst)
    except Exception as e:
        print("Une erreur est survenue:", e)

# Fonction pour vérifier une seule adresse IP
def check_ip(ip):
    try:
        paquet = IP(dst=ip) / ICMP()
        print("scan de ", ip)
        send(paquet)
        reply = sr1(paquet, timeout=3)
        if reply is not None:
            print(f"{ip} est ONLINE")
        else:
            print("%s n'est pas joignable pour le moment" % paquet[IP].dst)
    except Exception as e:
        print("Une erreur est survenue:", e)

# Fonction principale
def main():
    # Définition des arguments en utilisant argparse
    parser = argparse.ArgumentParser(description='Scan IP addresses.')
    parser.add_argument('ip', type=str, help='Adresse IP à vérifier')
    parser.add_argument('-t', action='store_true', help='Exécute la vérification pour toutes les adresses IP')
    parser.add_argument('-a', action='store_true', help='Executer la vérification pour une seule adresse IP')

    # Analyse des arguments de la ligne de commande
    args = parser.parse_args()
    ip_to_check = args.ip

    # Gestion du signal d'interruption (Ctrl + C)
    signal.signal(signal.SIGINT, signal_handler)

    # Choix du mode de vérification en fonction des arguments
    if args.t:
        check_mult_ip(ip_to_check)
    elif args.a:
        check_ip(ip_to_check)
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
