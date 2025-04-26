
rule Backdoor_Linux_Mirai_bd_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.bd!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 08 00 00 "
		
	strings :
		$a_00_0 = {2f 76 61 72 2f 62 69 6e 3b 77 67 65 74 20 2d 4f 20 64 6d 69 70 73 20 25 73 3b 63 68 6d 6f 64 20 2b 78 20 2f 76 61 72 2f 62 69 6e 2f 64 6d 69 70 73 3b 28 6b 69 6c 6c 61 6c 6c 20 2d 39 20 74 65 6c 6e 65 74 64 20 7c 7c 20 6b 69 6c 6c 20 2d 39 20 74 65 6c 6e 65 74 64 } //1 /var/bin;wget -O dmips %s;chmod +x /var/bin/dmips;(killall -9 telnetd || kill -9 telnetd
		$a_00_1 = {65 78 70 6c 6f 69 74 20 66 61 69 6c 65 64 } //1 exploit failed
		$a_00_2 = {48 54 54 50 20 25 73 20 66 6c 6f 6f 64 69 6e 67 20 25 73 20 77 69 74 68 20 25 64 20 70 6f 77 65 72 } //1 HTTP %s flooding %s with %d power
		$a_00_3 = {61 6c 73 6f 20 6e 6f 74 20 61 20 64 64 6f 73 20 70 61 63 6b 65 74 } //1 also not a ddos packet
		$a_00_4 = {70 68 70 62 6f 74 } //1 phpbot
		$a_00_5 = {62 79 70 61 73 73 69 6e 67 20 61 75 74 68 } //1 bypassing auth
		$a_00_6 = {41 4b 2d 34 37 20 53 43 41 4e 4e 45 52 20 53 54 41 52 54 45 44 21 } //1 AK-47 SCANNER STARTED!
		$a_00_7 = {4b 69 6c 6c 69 6e 67 20 70 69 64 20 25 64 } //1 Killing pid %d
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=5
 
}