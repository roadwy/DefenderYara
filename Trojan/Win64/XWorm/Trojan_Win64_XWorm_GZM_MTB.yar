
rule Trojan_Win64_XWorm_GZM_MTB{
	meta:
		description = "Trojan:Win64/XWorm.GZM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 89 c7 48 89 d9 e8 ?? ?? ?? ?? 48 89 c1 4c 89 f2 e8 ?? ?? ?? ?? 49 89 c4 48 c7 44 24 ?? 00 00 00 00 41 b8 04 00 00 00 48 89 f9 4c 89 fa 41 b9 04 00 00 00 ff d0 48 c7 44 24 ?? 00 00 00 00 4c 8d 05 ?? ?? ?? ?? 41 b9 04 00 00 00 48 89 f9 4c 89 fa e8 ?? ?? ?? ?? 48 c7 44 24 ?? 00 00 00 00 41 b8 04 00 00 00 48 89 f9 4c 89 fa 45 31 c9 41 ff d4 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}