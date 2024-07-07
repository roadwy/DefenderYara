
rule Backdoor_Linux_Gafgyt_Q_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.Q!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_00_0 = {42 6f 74 20 64 65 70 6c 6f 79 20 73 75 63 63 65 73 73 } //1 Bot deploy success
		$a_00_1 = {53 65 6e 64 53 54 44 48 45 58 } //1 SendSTDHEX
		$a_00_2 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //1 npxXoudifFeEgGaACScs
		$a_00_3 = {48 54 54 50 46 4c 4f 4f 44 } //1 HTTPFLOOD
		$a_00_4 = {55 44 50 20 46 6c 6f 6f 64 69 6e 67 20 25 73 20 66 6f 72 20 25 64 20 73 65 63 6f 6e 64 73 } //1 UDP Flooding %s for %d seconds
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=3
 
}