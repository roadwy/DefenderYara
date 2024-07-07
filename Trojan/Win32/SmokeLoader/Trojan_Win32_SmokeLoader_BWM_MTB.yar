
rule Trojan_Win32_SmokeLoader_BWM_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.BWM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c7 d3 e8 89 35 90 01 04 03 45 90 01 01 89 45 90 01 01 33 45 90 01 01 31 45 90 01 01 8b 45 90 01 01 29 45 90 01 01 81 45 e0 90 01 04 ff 4d 90 01 01 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}