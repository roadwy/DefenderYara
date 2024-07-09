
rule Backdoor_Linux_Mirai_CG_xp{
	meta:
		description = "Backdoor:Linux/Mirai.CG!xp,SIGNATURE_TYPE_ELFHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 40 9e 00 d4 93 bf 00 1c 48 00 ?? ?? 80 01 00 24 83 a1 00 14 83 c1 00 18 7c 08 03 a6 83 e1 00 1c 38 21 00 20 4e 80 00 20 38 80 00 09 3b a0 } //1
		$a_00_1 = {3c e0 10 01 38 e7 d3 7c 3c 60 10 00 38 63 68 28 48 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}