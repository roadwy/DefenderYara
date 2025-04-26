
rule Trojan_Win32_Redline_GTC_MTB{
	meta:
		description = "Trojan:Win32/Redline.GTC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 02 33 c1 8b 0d ?? ?? ?? ?? 03 8d ?? ?? ?? ?? 88 01 83 3d ?? ?? ?? ?? 20 75 13 90 0a 46 00 0f b6 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 95 } //10
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}
rule Trojan_Win32_Redline_GTC_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GTC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f4 33 d2 f7 75 ?? 8b 4d ?? 0f be 04 11 6b c0 ?? 6b c0 ?? 99 b9 ?? ?? ?? ?? f7 f9 6b c0 ?? 6b c0 ?? 8b 55 0c 03 55 f4 0f b6 0a 33 c8 8b 55 0c 03 55 f4 88 0a eb } //10
		$a_01_1 = {31 f2 8b 75 b4 01 ce 89 34 24 89 7c 24 04 89 54 24 08 89 45 a8 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10) >=10
 
}