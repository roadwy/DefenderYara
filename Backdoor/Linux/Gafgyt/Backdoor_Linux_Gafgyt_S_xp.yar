
rule Backdoor_Linux_Gafgyt_S_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.S!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {4c 6f 6c 69 20 42 6f 74 } //3 Loli Bot
		$a_00_1 = {47 48 50 20 25 73 20 46 6c 6f 6f 64 69 6e 67 20 25 73 3a 25 64 20 66 6f 72 20 25 64 } //1 GHP %s Flooding %s:%d for %d
		$a_00_2 = {42 72 75 74 65 64 20 61 20 54 65 6c 6e 65 74 } //1 Bruted a Telnet
		$a_00_3 = {49 6e 63 6f 6d 69 6e 67 20 4c 6f 6c 69 } //1 Incoming Loli
		$a_02_4 = {63 64 20 2f 74 6d 70 3b 20 62 75 73 79 62 6f 78 20 77 67 65 74 20 68 74 74 70 3a 2f 2f [0-30] 2f 6c 6f 6c 69 2e 73 68 3b 20 63 68 6d 6f 64 20 37 37 37 20 6c 6f 6c 69 2e 73 68 } //2
	condition:
		((#a_00_0  & 1)*3+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*2) >=5
 
}