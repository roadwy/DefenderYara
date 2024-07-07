
rule Trojan_Win32_SmokeLoader_N_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.N!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d f8 8d 04 13 d3 ea 89 45 ec c7 05 90 01 04 ee 3d ea f4 03 55 d8 8b 45 ec 31 45 fc 33 55 fc 81 3d 90 01 04 13 02 00 00 89 55 ec 75 14 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}