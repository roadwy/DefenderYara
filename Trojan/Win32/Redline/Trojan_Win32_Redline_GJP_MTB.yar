
rule Trojan_Win32_Redline_GJP_MTB{
	meta:
		description = "Trojan:Win32/Redline.GJP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c2 83 e2 03 0f b6 92 20 74 45 00 30 90 20 c8 43 00 83 c0 01 3d 00 ac 01 00 75 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GJP_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GJP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 da 88 55 df 0f b6 45 df f7 d0 88 45 df 0f b6 4d df 2b 4d e0 88 4d df 0f b6 55 df f7 d2 88 55 df 0f b6 45 df 03 45 e0 88 45 df 8b 4d e0 8a 55 df 88 54 0d e4 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GJP_MTB_3{
	meta:
		description = "Trojan:Win32/Redline.GJP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f be c0 69 c8 ?? ?? ?? ?? ba ?? ?? ?? ?? 89 c8 f7 ea c1 fa ?? 89 c8 c1 f8 ?? 29 c2 89 d0 89 c2 89 d0 c1 e0 ?? 01 d0 89 c1 8b 55 ec 8b 45 0c 01 d0 31 cb 89 da 88 10 83 45 ec } //10
		$a_03_1 = {0f be c0 69 c8 ?? ?? ?? ?? ba ?? ?? ?? ?? 89 c8 f7 ea 8d 04 0a c1 f8 ?? 89 c2 89 c8 c1 f8 ?? 29 c2 89 d0 89 c2 89 d0 c1 e0 ?? 01 d0 01 c0 01 d0 89 c1 8b 55 ec 8b 45 0c 01 d0 31 cb 89 da 88 10 83 45 ec } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=10
 
}