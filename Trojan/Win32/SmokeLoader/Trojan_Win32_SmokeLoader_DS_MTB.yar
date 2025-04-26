
rule Trojan_Win32_SmokeLoader_DS_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.DS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4c 24 18 8d 14 37 d3 ee 8b 4c 24 2c 8d 44 24 1c 89 54 24 28 89 74 24 1c c7 05 [0-04] ee 3d ea f4 e8 [0-04] 8b 44 24 28 31 44 24 10 81 3d [0-04] e6 09 00 00 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}