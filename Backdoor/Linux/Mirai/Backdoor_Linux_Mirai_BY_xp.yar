
rule Backdoor_Linux_Mirai_BY_xp{
	meta:
		description = "Backdoor:Linux/Mirai.BY!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c4 10 80 7f 14 1f 77 2a 8b 5f 10 e8 ?? ?? 00 00 66 c1 cb 08 c1 cb 10 66 c1 cb 08 31 c9 8a 4f 14 d3 e8 01 d8 66 c1 c8 08 c1 c8 10 66 c1 c8 08 89 46 10 } //1
		$a_00_1 = {b9 cd cc cc cc 89 c3 f7 e1 89 54 24 0c 89 44 24 08 8b 54 24 0c 89 d8 c1 ea 02 8d 14 92 29 d0 83 f8 04 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}