
rule Backdoor_Linux_Mirai_CA_xp{
	meta:
		description = "Backdoor:Linux/Mirai.CA!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {30 43 e2 19 00 53 e3 0c 20 cb 97 05 3a 8d 92 70 } //1
		$a_00_1 = {31 a0 e1 02 30 83 e0 24 21 13 e5 1f 10 00 e2 32 21 a0 e1 01 00 12 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}