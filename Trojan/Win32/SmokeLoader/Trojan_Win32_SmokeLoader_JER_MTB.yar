
rule Trojan_Win32_SmokeLoader_JER_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.JER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 8b 4d 90 01 01 c7 05 90 01 08 89 45 90 01 01 8d 45 90 01 01 e8 90 01 04 8b 45 90 01 01 31 45 90 01 01 8b 45 90 01 01 31 45 90 01 01 83 3d 90 01 05 0f 85 90 00 } //1
		$a_03_1 = {d3 e8 8b 4d 90 01 01 89 45 e8 8d 45 e8 e8 90 01 04 8b 45 e8 33 c3 31 45 f8 89 35 90 01 04 8b 45 f4 89 45 e0 8b 45 f8 29 45 e0 8b 45 e0 89 45 f4 81 45 e4 90 01 04 ff 4d d8 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}