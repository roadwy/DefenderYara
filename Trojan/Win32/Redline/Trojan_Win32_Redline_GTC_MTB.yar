
rule Trojan_Win32_Redline_GTC_MTB{
	meta:
		description = "Trojan:Win32/Redline.GTC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0f b6 02 33 c1 8b 0d 90 01 04 03 8d 90 01 04 88 01 83 3d 90 01 04 20 75 13 90 0a 46 00 0f b6 0d 90 01 04 8b 15 90 01 04 03 95 90 00 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //00 00  VirtualProtect
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_GTC_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GTC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 45 f4 33 d2 f7 75 90 01 01 8b 4d 90 01 01 0f be 04 11 6b c0 90 01 01 6b c0 90 01 01 99 b9 90 01 04 f7 f9 6b c0 90 01 01 6b c0 90 01 01 8b 55 0c 03 55 f4 0f b6 0a 33 c8 8b 55 0c 03 55 f4 88 0a eb 90 00 } //0a 00 
		$a_01_1 = {31 f2 8b 75 b4 01 ce 89 34 24 89 7c 24 04 89 54 24 08 89 45 a8 } //00 00 
	condition:
		any of ($a_*)
 
}