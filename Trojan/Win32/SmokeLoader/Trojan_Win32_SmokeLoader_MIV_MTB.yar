
rule Trojan_Win32_SmokeLoader_MIV_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.MIV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 8b 4d 90 01 01 c7 05 90 01 08 89 45 90 01 01 8d 45 90 01 01 e8 90 01 04 8b 45 90 01 01 31 45 fc 8b 45 fc 31 45 f8 81 3d 90 01 08 75 90 00 } //1
		$a_03_1 = {d3 ea 89 55 f8 8b 45 90 01 01 01 45 f8 8b 45 f8 33 c7 31 45 fc 89 35 90 01 04 8b 45 f4 89 45 90 01 01 8b 45 90 01 01 29 45 90 01 01 8b 45 90 01 01 89 45 90 01 01 8d 45 90 01 01 e8 90 01 04 ff 4d 90 01 01 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}