
rule Trojan_Win32_Redline_GJM_MTB{
	meta:
		description = "Trojan:Win32/Redline.GJM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {88 45 df 0f b6 4d df c1 f9 02 0f b6 55 df c1 e2 06 0b ca 88 4d df 0f b6 45 df 03 45 e0 88 45 df 0f b6 4d df f7 d1 88 4d df 0f b6 55 df c1 fa 05 0f b6 45 df c1 e0 03 0b d0 88 55 df 8b 4d e0 8a 55 df 88 54 0d e4 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_GJM_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GJM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {8b 45 c0 33 d2 f7 75 b4 8b 45 10 0f b6 14 10 33 ca 88 4d eb 8b 45 08 03 45 c0 8a 08 88 4d be 0f b6 55 eb 8b 45 08 03 45 c0 0f b6 08 03 ca 8b 55 08 03 55 c0 88 0a 0f b6 45 be 8b 4d 08 03 4d c0 0f b6 11 2b d0 8b 45 08 03 45 c0 88 10 eb } //01 00 
		$a_03_1 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 90 02 20 5c 00 52 00 65 00 67 00 53 00 76 00 63 00 73 00 2e 00 65 00 78 00 65 00 90 00 } //01 00 
		$a_01_2 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //00 00  VirtualProtect
	condition:
		any of ($a_*)
 
}