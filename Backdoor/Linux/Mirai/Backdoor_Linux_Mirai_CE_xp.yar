
rule Backdoor_Linux_Mirai_CE_xp{
	meta:
		description = "Backdoor:Linux/Mirai.CE!xp,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {c0 30 9f e5 00 30 d3 e5 00 00 53 e3 d3 ff ff 0a b0 30 9f e5 00 30 d3 e5 c0 } //1
		$a_00_1 = {30 4b e5 14 30 1b e5 23 34 a0 e1 14 30 0b e5 0d 30 5b e5 a3 31 a0 e1 0d 30 4b e5 0d 30 5b e5 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}