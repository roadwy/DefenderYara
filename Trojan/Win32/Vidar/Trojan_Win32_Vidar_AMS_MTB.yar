
rule Trojan_Win32_Vidar_AMS_MTB{
	meta:
		description = "Trojan:Win32/Vidar.AMS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c0 89 44 24 [0-28] 30 04 29 45 3b 6b 04 0f 8c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Vidar_AMS_MTB_2{
	meta:
		description = "Trojan:Win32/Vidar.AMS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 a4 2b d0 8b 45 d4 31 10 83 45 ec 04 83 45 d4 04 8b 45 ec 3b 45 d0 72 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}