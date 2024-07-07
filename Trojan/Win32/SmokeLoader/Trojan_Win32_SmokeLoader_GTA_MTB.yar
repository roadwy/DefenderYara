
rule Trojan_Win32_SmokeLoader_GTA_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.GTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 8b 4d 90 01 01 c7 05 90 01 08 89 45 e4 8d 45 e4 e8 90 01 04 8b 45 90 01 01 31 45 90 01 01 8b 7d 90 01 01 33 7d 90 01 01 83 3d 90 01 05 75 90 00 } //1
		$a_03_1 = {d3 e8 8b 4d 90 01 01 89 45 90 01 01 8d 45 90 01 01 e8 90 01 04 8b 45 e4 33 c7 31 45 fc 89 35 90 01 04 8b 45 f4 89 45 e8 8b 45 fc 29 45 e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}