
rule Backdoor_Linux_Mirai_CB_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.CB!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 0a 00 00 "
		
	strings :
		$a_00_0 = {68 61 63 6b 6d 79 } //1 hackmy
		$a_00_1 = {6d 69 72 61 69 2e 6c 69 6e 75 78 } //1 mirai.linux
		$a_00_2 = {62 75 73 79 62 6f 74 6e 65 74 } //1 busybotnet
		$a_00_3 = {47 41 4c 41 58 59 20 5d 20 52 65 6d 6f 76 69 6e 67 20 54 65 6d 70 20 44 69 72 65 63 74 6f 72 79 73 2e 20 7c 7c 20 49 50 3a 20 25 73 20 7c 7c 20 50 6f 72 74 3a 20 32 33 20 7c 7c 20 55 73 65 72 6e 61 6d 65 3a 20 25 73 20 7c 7c 20 50 61 73 73 77 6f 72 64 3a 20 25 73 } //1 GALAXY ] Removing Temp Directorys. || IP: %s || Port: 23 || Username: %s || Password: %s
		$a_00_4 = {70 6b 69 6c 6c 20 2d 39 20 25 73 3b 6b 69 6c 6c 61 6c 6c 20 2d 39 20 25 73 3b } //1 pkill -9 %s;killall -9 %s;
		$a_00_5 = {73 65 72 76 69 63 65 20 69 70 74 61 62 6c 65 73 20 73 74 6f 70 } //1 service iptables stop
		$a_00_6 = {73 65 72 76 69 63 65 20 66 69 72 65 77 61 6c 6c 64 20 73 74 6f 70 } //1 service firewalld stop
		$a_00_7 = {4d 69 72 61 69 53 63 61 6e 6e 65 72 } //1 MiraiScanner
		$a_00_8 = {54 65 6c 6e 65 74 53 63 61 6e 6e 65 72 } //1 TelnetScanner
		$a_00_9 = {4d 69 72 61 69 49 50 52 61 6e 67 65 73 } //1 MiraiIPRanges
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1) >=5
 
}