
rule Trojan_Win32_Redline_RJ_MTB{
	meta:
		description = "Trojan:Win32/Redline.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {c6 45 e8 e9 c6 45 e9 29 c6 45 ea 35 c6 45 eb f4 c6 45 ec 73 c6 45 ed f5 c6 45 ee 66 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_RJ_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 45 c4 0f 00 00 00 c7 45 c0 0a 00 00 00 c7 45 b0 71 6a 68 7a c7 45 b4 65 64 7a 75 66 c7 45 b8 64 6e c6 45 ba 00 c7 45 c8 00 00 00 00 c7 45 d8 00 00 00 00 c7 45 dc 0f 00 00 00 c6 45 c8 00 c7 45 f0 03 00 00 00 83 ec 0c 8a 45 e0 88 44 24 04 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_RJ_MTB_3{
	meta:
		description = "Trojan:Win32/Redline.RJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0b c1 88 45 90 01 01 0f b6 55 90 01 01 83 f2 90 01 01 88 55 90 01 01 0f b6 45 90 01 01 d1 90 01 01 0f b6 4d 90 01 01 c1 e1 90 01 01 0b c1 88 45 90 01 01 0f b6 55 90 01 01 f7 da 88 55 90 01 01 0f b6 45 90 01 01 c1 f8 90 01 01 0f b6 4d 90 01 01 d1 90 01 01 0b c1 88 45 90 01 01 0f b6 55 90 01 01 f7 d2 88 55 90 01 01 0f b6 45 90 01 01 2d 90 01 04 88 45 90 01 01 8b 4d 90 01 01 8a 55 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}