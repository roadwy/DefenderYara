
rule Backdoor_Linux_Mirai_BI_xp{
	meta:
		description = "Backdoor:Linux/Mirai.BI!xp,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6b 69 6c 6c 65 72 20 66 69 6e 69 73 68 65 64 } //1 killer finished
		$a_01_1 = {6b 69 6c 6c 65 64 20 70 69 64 } //1 killed pid
		$a_01_2 = {6d 61 6c 69 63 69 6f 75 73 20 70 69 64 } //1 malicious pid
		$a_01_3 = {68 6c 4c 6a 7a 74 71 5a } //1 hlLjztqZ
		$a_01_4 = {6e 70 78 58 6f 75 64 69 66 46 65 45 67 47 61 41 43 53 63 73 } //1 npxXoudifFeEgGaACScs
		$a_01_5 = {6b 69 6c 6c 65 64 20 6d 61 6c 69 63 69 6f 75 73 } //1 killed malicious
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}