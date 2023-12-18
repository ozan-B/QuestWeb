from ipwhois import IPWhois




def  print_network_data(data):
    for key, value in data.items():

        if isinstance(value, dict):
            #print(type(value))
            print(f"\033[96m{key.capitalize()}:\033[0m")
            print_network_data(f"{value}")

        elif isinstance(value, list):
            

            print(f"\033[96m{key.capitalize()}:\033[0m")
            #print(value)
            for i in value:
                #print(f"{i}------------{type(i)}")
                if isinstance(i,str):#burayı links keyi için yazdım
                    print(f"\033\t\t\t[93m{i}\033[0m")
                elif isinstance(i,dict):#diğerlerinin hepsi dict zaten
                    for key_sub,value_sub in i.items():
                        print(f"\033[93m\t\t\t{key_sub.capitalize()}:\033[0m{value_sub}")


            #for inner_value in value:
                #print_network_data(inner_value, indent + 1)

        elif isinstance(value, str):
            #print(type(value))

            print(f"\033[96m{key.capitalize()}:".ljust(30) + f"\033[0m{value}")

        else:
            #print(type(value))
            print(f"\033[96m{key.capitalize()}:\033[0m{value}")




def whois_lookup(ip_address):
    try:
        # IPWhois sorgusu yap
        ip_address = ip_address.strip()
        obj = IPWhois(ip_address)
        result = obj.lookup_rdap()

        first_result_items=["asn_registry","asn","asn_cidr","asn_country_code","asn_date","asn_description"]
        # En uzun anahtarın uzunluğunu bul
        first_max_key_length = max(len(key) for key in first_result_items)
        print(first_max_key_length)
        
        for i in first_result_items:
            # Çıktıyı okunabilir hale getir
            print(f"\033[96m{i.capitalize()}:".ljust(first_max_key_length + 15) + f"\033[0m{result.get(i, '')}")
        print("\n\n") 
        




        network_max_key_length = max(len(key) for key in first_result_items)
        network_data = result.get("network", {})
        print("\033[91mNetwork Information:\033[0m")
        print_network_data(network_data)
    




        
        entities = result.get("entities", [])
        ozan=''
        for i in entities:
            ozan = ozan+i
        print("\033[91m\n\nEntients:\033[0m".ljust(34)+ozan)
            
                                
        objects = result.get("objects", {})
        print("\033[91m\n\nObjects:\033[0m")


        for entity_key, entity_value in objects.items():

            #print(f"  {entity_key}: {entity_value}")

            for key, value in entity_value.items():
                if isinstance(value, list):
                    if value != None:
                        print(f"\033[93m\t{key}:".ljust(10)  +  f"\033[0m {', '.join(map(str,value))}")
                elif isinstance(value, dict):
                    if value != None:
                        print(f"\033[93m\t{key}:".ljust(10)  +f"\033[0m{value}\n")
                    for sub_key, sub_value in value.items():
                        if sub_value != None:
                            print(f"\033[93m\t{sub_key}:"  .ljust(10)  + f"\033[0m {sub_value}")

                else:
                    if value != None:
                        print(f"\033[93m\t{key}:".ljust(10)  + f"\033[0m {value}\n")

    except Exception as e:
        print(f"Hata: {e}")

# Kullanıcıdan IP adresi girişi al
ip_address = input("Whois sorgusu için IP adresi girin: ")

# Whois sorgusu yap
whois_lookup(ip_address)
