
rule Backdoor_Linux_Gafgyt_M_xp{
	meta:
		description = "Backdoor:Linux/Gafgyt.M!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 74 61 72 74 54 68 65 4c 65 6c 7a } //1 StartTheLelz
		$a_00_1 = {73 65 6e 64 55 44 50 } //1 sendUDP
		$a_00_2 = {73 65 6e 64 54 43 50 } //1 sendTCP
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}