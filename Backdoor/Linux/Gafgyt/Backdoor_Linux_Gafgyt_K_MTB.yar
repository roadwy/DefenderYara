
rule Backdoor_Linux_Gafgyt_K_MTB{
	meta:
		description = "Backdoor:Linux/Gafgyt.K!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {55 44 50 46 4c 4f 4f 44 } //1 UDPFLOOD
		$a_01_1 = {53 54 4f 50 41 54 54 } //1 STOPATT
		$a_01_2 = {68 6c 4c 6a 7a 74 71 } //1 hlLjztq
		$a_01_3 = {4b 49 4c 4c 41 54 54 4b } //1 KILLATTK
		$a_01_4 = {50 52 4f 54 5f 45 58 45 43 } //1 PROT_EXEC
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}