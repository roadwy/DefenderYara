
rule Trojan_Win32_SmokeLoader_CZ_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.CZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c3 d3 e8 8b 4d 90 01 01 89 45 90 01 01 8d 45 fc e8 90 01 04 8b 45 90 01 01 31 45 90 01 01 8b 45 90 01 01 31 45 90 01 01 89 3d 90 01 04 8b 45 90 01 01 89 45 90 01 01 8b 45 90 01 01 29 45 90 01 01 8b 45 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_SmokeLoader_CZ_MTB_2{
	meta:
		description = "Trojan:Win32/SmokeLoader.CZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 ea 8b 4c 24 34 8d 44 24 28 c7 05 90 02 04 ee 3d ea f4 89 54 24 28 e8 90 02 04 8b 44 24 20 31 44 24 10 81 3d 90 02 04 e6 09 00 00 75 08 56 56 ff 15 90 02 04 8b 44 24 10 31 44 24 28 8b 44 24 28 83 44 24 18 64 29 44 24 18 83 6c 24 18 64 83 3d 90 02 04 0c 75 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}