
rule Backdoor_Linux_Mirai_BM_xp{
	meta:
		description = "Backdoor:Linux/Mirai.BM!xp,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {89 c2 83 ee 02 c1 e2 0b 31 c2 44 89 c0 c1 e8 13 89 d1 44 31 c0 c1 e9 08 31 c2 31 d1 66 89 0f 48 83 c7 02 } //01 00 
		$a_00_1 = {0f b6 85 a7 f7 ff ff 85 c0 89 85 ac f7 ff ff 0f 8e fd 00 00 00 44 89 f8 4c 8b ad 98 f7 ff ff 4c 8b a5 98 f7 ff ff 66 c1 c8 08 66 89 85 be f7 ff ff 8b 85 ac f7 ff ff 45 31 f6 49 83 c5 02 ff c8 48 ff c0 48 89 85 88 f7 ff ff } //00 00 
	condition:
		any of ($a_*)
 
}