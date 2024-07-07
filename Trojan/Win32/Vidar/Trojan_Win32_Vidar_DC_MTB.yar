
rule Trojan_Win32_Vidar_DC_MTB{
	meta:
		description = "Trojan:Win32/Vidar.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 45 a4 33 c0 89 45 a4 8b 45 c8 03 45 a0 03 45 ec 03 45 a4 8b 55 d8 31 02 83 45 ec 04 83 45 d8 04 8b 45 ec 3b 45 d4 0f 82 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}