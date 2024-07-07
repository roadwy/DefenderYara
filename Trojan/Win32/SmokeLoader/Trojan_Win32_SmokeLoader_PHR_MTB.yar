
rule Trojan_Win32_SmokeLoader_PHR_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.PHR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {d3 ea 8b 4c 24 90 01 01 03 c7 89 44 24 90 01 01 8d 44 24 2c 89 54 24 2c c7 05 90 01 08 e8 90 01 04 8b 44 24 24 31 44 24 14 81 3d 90 01 08 75 90 00 } //1
		$a_03_1 = {d3 ee 03 74 24 90 01 01 8b 44 24 90 01 01 31 44 24 14 81 3d 90 01 08 75 90 01 01 53 53 53 ff 15 90 01 04 8b 44 24 14 33 c6 89 44 24 14 2b f8 8d 44 24 90 01 01 e8 90 01 04 83 6c 24 34 01 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}