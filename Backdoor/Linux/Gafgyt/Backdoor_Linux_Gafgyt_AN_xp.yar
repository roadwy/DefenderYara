
rule Backdoor_Linux_Gafgyt_AN_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.AN!xp,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {42 30 54 4b 31 4c 4c } //2 B0TK1LL
		$a_01_1 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //1 npxXoudifFeEgGaACScs
		$a_01_2 = {43 6f 6e 6e 65 63 74 69 6f 6e 20 52 65 66 75 73 65 64 20 44 75 65 20 54 6f 20 44 75 70 65 } //1 Connection Refused Due To Dupe
		$a_01_3 = {6d 69 70 73 65 6c } //1 mipsel
		$a_01_4 = {68 6c 4c 6a 7a 74 71 5a } //1 hlLjztqZ
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}