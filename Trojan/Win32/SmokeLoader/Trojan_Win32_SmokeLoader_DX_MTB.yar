
rule Trojan_Win32_SmokeLoader_DX_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.DX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d0 d3 e2 8b c8 c1 e9 90 01 01 03 4d dc 03 55 e0 c7 05 90 01 08 33 d1 8b 4d f4 03 c8 33 d1 8b 0d 90 01 04 2b fa 81 f9 90 01 04 75 0c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}