
rule Backdoor_Linux_Mirai_B_xp{
	meta:
		description = "Backdoor:Linux/Mirai.B!xp,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {55 44 50 52 41 57 } //1 UDPRAW
		$a_00_1 = {4e 65 6d 65 73 69 73 20 69 6e 66 65 63 74 69 6f 6e 20 73 75 63 63 65 73 73 } //1 Nemesis infection success
		$a_00_2 = {4b 49 4c 4c 42 4f 54 } //1 KILLBOT
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}