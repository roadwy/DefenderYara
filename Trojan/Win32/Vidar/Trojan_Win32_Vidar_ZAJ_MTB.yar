
rule Trojan_Win32_Vidar_ZAJ_MTB{
	meta:
		description = "Trojan:Win32/Vidar.ZAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d a4 24 00 00 00 00 8b 0d f4 b8 45 00 69 c9 90 01 04 81 c1 c3 9e 26 00 89 0d f4 b8 45 00 8a 15 f6 b8 45 00 30 14 1e 83 ff 0f 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}