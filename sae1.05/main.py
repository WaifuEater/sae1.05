from scapy.all import *
import argparse
import signal
import ipaddress
import time
import sys

# Ces lignes importent les bibliothèques nécessaires au programme, telles que Scapy pour la manipulation des paquets réseau, 
# argparse pour l'analyse des arguments de ligne de commande, signal pour gérer les signaux du système, ipaddress pour traiter les adresses IP, 
# time pour les opérations liées au temps, et sys pour les fonctionnalités système.



# NON UTILISÉ, liste de ports commun, pour une future fonction type nmap, marche mais prend beaucoup trop de temps alors désactivé avant
#  d'avoir trouvé un fix
#  common = [80, 443, 67, 68, 20, 21, 23, 22, 53, 8080, 123, 25, 3389, 110, 554, 445, 587, 993, 137, 139, 8008, 500, 143, 161, 162, 389, 1434, 5900]



ip_valides = list()
# Déclare une liste vide pour stocker les addresse ip ayant répondu afin de faciliter le renvoi des ips ayant répondu 



def signal_handler(sig, frame):
    print("\nCtrl + C pressed [·]\nExiting...")
    sys.exit(0)
    
# La fonction signal_handler est appelée lorsqu'un signal de type Ctrl+C est détecté
# Elle affiche un message et quitte le programme de manière propre.
# Ce type de fonction n'est pas forcement nécéssaire mais ici la manière dont scapy gère le terminal 
# peut empécher l'utilisation du signal d'intéruption




def export_results(ip_list, export_file):
    if export_file and not hasattr(export_results, 'exported'):
        try:
            with open(export_file.name, 'w') as file:
                for ip in ip_list:
                    file.write(f"{ip} est ONLINE\n")
            print(f"Résultats exportés dans {export_file.name}")
            export_results.exported = True
        except Exception as e:
            print(f"Erreur lors de l'exportation des résultats dans {export_file.name}: {e}")

# La fonction export_results prend une liste d'adresses IP valides et un fichier d'export en argument,
# puis écrit chaque adresse IP dans le fichier avec un message indiquant qu'elle est en ligne. 
# Elle gère également les erreurs d'exportation.




def check_mult_ip(ip, export_file=None, num_hosts=256):
    try:
        ip_obj = ipaddress.ip_network(ip, strict=False)
        end_range = num_hosts  
        prefix_length = ip_obj.prefixlen
        # Extrait le subnet
        subnet = ip_obj.network_address
        octets = list(subnet.packed)  # Convertir en liste modifiable

# La fonction check_mult_ip prend une adresse IP, un fichier d'export 
# (optionnel), et un nombre d'hôtes à vérifier (par défaut 256). Elle utilise la bibliothèque ipaddress pour créer un objet réseau IP, 
# puis extrait la longueur du préfixe, le sous-réseau et les octets.
        

# -- Première section (si l'adresse IP spécifiée a un préfixe de 24, 16 ou 8) : --
        if ip_obj.num_addresses > 1:
            if prefix_length in [24, 16, 8]:
                octets_to_update = 4 - (prefix_length // 8)
                for i in range(end_range):
                    octets[-octets_to_update] = i  # Utiliser le négatif pour modifier l'octet à droite
                    host_ip = '.'.join(map(str, octets))
                    paquet = IP(dst=host_ip) / ICMP()
                    print(f"Scan de {host_ip}")
                    reply = sr1(paquet, timeout=3)
                    if reply is not None:
                        ip_valides.append(host_ip)
                        print(f"[✓] {host_ip} est ONLINE [✓]")
                    else:
                        print(f"[X] {host_ip} n'est pas joignable pour le moment [X]")
                    time.sleep(0.1)
                    # Sortir de la boucle si le nombre d'hôtes spécifié est atteint
                    if len(ip_valides) >= num_hosts:
                        break
                    
# Cette section s'applique lorsque l'adresse IP spécifiée a un préfixe de 24, 16 ou 8. Elle utilise une boucle for pour itérer 
# sur les adresses IP dans la plage spécifiée, en modifiant le dernier octet de l'adresse IP. Ensuite, 
# elle envoie un paquet ICMP à chaque adresse IP et vérifie si une réponse est reçue.
                    

# -- Deuxième section (si l'adresse IP donné n'utilise pas de masque) --            
        else:
            for i in range(end_range):
                octets[-1] = i  # Utiliser -1 pour modifier le dernier octet
                host_ip = '.'.join(map(str, octets))
                paquet = IP(dst=host_ip) / ICMP()
                print(f"Scan de {host_ip}")
                reply = sr1(paquet, timeout=3)
                if reply is not None:
                    ip_valides.append(host_ip)
                    print(f"[✓] {host_ip} est ONLINE [✓]")
                else:
                    print(f"[X] {host_ip} n'est pas joignable pour le moment [X]")
                time.sleep(0.1)
                # Sortir de la boucle si le nombre d'hôtes spécifié est atteint
                if len(ip_valides) >= num_hosts:
                    break

# Cette section s'applique lorsque l'adresse IP spécifiée n'a qu'une seule adresse dans le réseau. 
# Elle utilise une logique similaire pour itérer sur les adresses IP, en modifiant également le dernier octet, 
# puis envoie des paquets ICMP pour vérifier la connectivité.


# -- Troisième et dèrnière séction (gestion des erreures et de l'export des résultats)
    except ValueError as e:
        print(f"[?] Une erreur est survenue: [?] \n Vérifiez que le format de l'adresse IP est correct.\n", e)
    finally:
        # Exportation des résultats à la fin même si aucune IP n'est valide
        export_results(ip_valides, export_file)

# Cette partie gère les erreurs potentielles lors de la création de l'objet IP. 
# En fin de compte, elle appelle la fonction export_results pour exporter les résultats, même s'il n'y a aucune adresse IP valide.



def check_ip(ip, export_file=None):
    try:
        paquet = IP(dst=ip) / ICMP()
        print("Scan de ", ip)
        replies, _ = sr(paquet, timeout=3)
        
        if replies:
            ip_valides.append(ip)
            print(f"[✓] {ip} est ONLINE [✓]")
        else:
            print("[X] %s n'est pas joignable pour le moment [X]" % paquet[IP].dst)
        
        export_results(ip_valides, export_file)
    except Exception as e:
        print("[?] Une erreur est survenue: [?]", e)

# La fonction check_ip prend une adresse IP en argument, crée un paquet ICMP, 
# envoie le paquet et vérifie s'il y a une réponse. Elle affiche ensuite un message indiquant si l'adresse IP est en ligne. 
# Les résultats sont également exportés à l'aide de la fonction export_results si nécéssaire.
# Elle fonctionne différement de la fonction check_mult_ip (beaucoup plus simple) pour des raisons de compatibilité et car c'était la première
# Fonction que j'ai faite sur le programme, elle n'as donc pas vraiment évolué avec le reste a part pour l'export de fichier et le timeout


def arp_display(pkt):
    if ARP in pkt and pkt[ARP].op in (1, 2):  # Si le paquet est une requête ou une réponse ARP
        return f"ARP {pkt[ARP].psrc} -> {pkt[ARP].pdst} ({pkt[ARP].hwsrc})"


def arp_check(ip, export_file=None):
    try:
        print("Écoute du trafic ARP...")
        duration = int(input("Entrez la durée d'écoute en secondes : "))
        # Utilisation de la fonction sniff de Scapy avec le paramètre prn
        ans = sniff(filter=f'arp and host {ip}', timeout=duration, prn=arp_display, store=0)
    except Exception as e:
        print("[?] Une erreur est survenue lors de l'écoute ARP: [?]", e)







def main():
    parser = argparse.ArgumentParser(description="Scan d'ip")
    parser.add_argument('ip', type=str, help='Adresse IP à vérifier')
    parser.add_argument('-t','--num_hosts', type=int, default=256, help="Scan une range d'ip : si ip/classe -t -> scan selon le format de 0-255 \n et si ip/classe ou non -t x -> scan x hotes.")
    parser.add_argument('-a', action='store_true', help="Execute la vérification d'une seule adresse IP")
    parser.add_argument('-p', action='store_true', help="Ecoute le traffic ARP pour un temp donné et renvoie si l'IP est présente dans le traffic. Si l'IP y figure, affiche l'adresse MAC correspondante") 
    parser.add_argument('-x', '--output_file', type=argparse.FileType('w'), help="Exporte l'output de la commande dans un fichier spécifié, par exemple : ip -x /path/du/fichier ou fichier, si non éxistant il en créera un.")
    
    args = parser.parse_args()
    ip_to_check = args.ip

    signal.signal(signal.SIGINT, signal_handler)
    
    if args.p:
        arp_check(ip_to_check, export_file=args.output_file)
    elif args.a:
        check_ip(ip_to_check, export_file=args.output_file)
    elif args.num_hosts:
        check_mult_ip(ip_to_check, export_file=args.output_file, num_hosts=args.num_hosts)
    else:
        print(f"Adresse IP à vérifier : {ip_to_check}")

if __name__ == "__main__":
    main()


# Et pour finir, la fonction main gère les arguments de ligne de commande à l'aide d'argparse. 
# Elle appelle les fonctions appropriées en fonction des options fournies, elle donne également une petite déscription des options et arguments.
# La gestion du signal Ctrl+C est configurée pour garantir une sortie propre du programme.
