
rule Trojan_Win32_SmokeLoader_DE_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e8 8b 55 ec 01 02 8b 45 d8 03 45 b0 03 45 e8 89 45 b4 8b 45 b4 8b 55 ec 31 02 83 45 e8 04 83 45 ec 04 8b 45 e8 3b 45 e4 72 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_SmokeLoader_DE_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 14 89 44 24 20 8b 44 24 28 01 44 24 20 8b 4c 24 1c 8b 54 24 14 d3 ea 8b 4c 24 38 8d 44 24 2c c7 05 90 02 04 ee 3d ea f4 89 54 24 2c e8 90 02 04 8b 44 24 20 31 44 24 10 81 3d 90 02 04 e6 09 00 00 75 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}