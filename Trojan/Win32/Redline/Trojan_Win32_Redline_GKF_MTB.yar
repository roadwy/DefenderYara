
rule Trojan_Win32_Redline_GKF_MTB{
	meta:
		description = "Trojan:Win32/Redline.GKF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 84 3c 90 01 04 03 44 24 14 0f b6 c0 8a 84 04 90 01 04 30 86 90 01 04 46 81 fe 90 01 04 0f 82 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Redline_GKF_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GKF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c0 01 89 85 90 01 04 8b 8d 90 01 04 3b 0d 90 01 04 73 90 01 01 0f b6 15 90 01 04 a1 90 01 04 03 85 90 01 04 0f b6 08 33 ca 8b 15 90 01 04 03 95 90 01 04 88 0a eb 90 00 } //10
		$a_01_1 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}