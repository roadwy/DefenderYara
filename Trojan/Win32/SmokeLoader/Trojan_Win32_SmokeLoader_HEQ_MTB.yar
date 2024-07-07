
rule Trojan_Win32_SmokeLoader_HEQ_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.HEQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 8b 4d 90 01 01 c7 05 90 01 08 89 45 90 01 01 8d 45 90 01 01 e8 90 01 04 8b 45 90 01 01 31 45 90 01 01 8b 45 90 01 01 31 45 90 01 01 83 3d 90 01 05 0f 85 90 00 } //1
		$a_03_1 = {d3 e8 8b 4d 90 01 01 89 45 90 01 01 8d 45 90 01 01 e8 90 01 04 8b 45 90 01 01 33 c3 31 45 90 01 01 89 35 90 01 04 8b 45 90 01 01 89 45 e4 8b 45 f8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}