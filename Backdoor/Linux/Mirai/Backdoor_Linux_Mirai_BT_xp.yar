
rule Backdoor_Linux_Mirai_BT_xp{
	meta:
		description = "Backdoor:Linux/Mirai.BT!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {30 43 e2 19 00 53 e3 0c 20 ca 97 05 3a 8d 92 64 } //1
		$a_00_1 = {00 c0 96 e5 51 3c 8d e2 ac 22 a0 e1 68 30 83 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}