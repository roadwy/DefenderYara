
rule Backdoor_Linux_Gafgyt_BG_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.BG!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {2f 75 73 72 2f 73 62 69 6e 2f 64 72 6f 70 62 65 61 72 } //2 /usr/sbin/dropbear
		$a_01_1 = {4b 49 4c 4c 41 54 54 4b } //2 KILLATTK
		$a_01_2 = {4c 4f 4c 4e 4f 47 54 46 4f } //2 LOLNOGTFO
		$a_01_3 = {42 4f 54 4b 49 4c 4c } //2 BOTKILL
		$a_01_4 = {42 4f 47 4f 4d 49 50 53 } //1 BOGOMIPS
		$a_01_5 = {68 6c 4c 6a 7a 74 71 5a } //1 hlLjztqZ
		$a_01_6 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //1 npxXoudifFeEgGaACScs
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}