
rule Trojan_Win32_Redline_GJN_MTB{
	meta:
		description = "Trojan:Win32/Redline.GJN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {89 c2 83 e2 03 0f b6 92 20 54 42 00 30 90 20 a8 40 00 83 c0 01 3d 00 ac 01 00 75 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_GJN_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GJN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {88 4d df 0f b6 55 df 03 55 e0 88 55 df 0f b6 45 df c1 f8 07 0f b6 4d df d1 e1 0b c1 88 45 df 0f b6 55 df 2b 55 e0 88 55 df 0f b6 45 df f7 d0 88 45 df 0f b6 4d df f7 d9 88 4d df 0f b6 55 df 81 ea aa 00 00 00 88 55 df 8b 45 e0 8a 4d df 88 4c 05 e4 } //00 00 
	condition:
		any of ($a_*)
 
}