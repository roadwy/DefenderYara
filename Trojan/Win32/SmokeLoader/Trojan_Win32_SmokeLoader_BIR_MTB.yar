
rule Trojan_Win32_SmokeLoader_BIR_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.BIR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d0 8b c8 c1 ea 05 03 54 24 34 c1 e1 04 03 4c 24 28 03 c3 33 d1 33 d0 2b fa 8b cf c1 e1 04 c7 05 90 01 04 00 00 00 00 89 4c 24 10 8b 44 24 2c 01 44 24 10 81 3d 90 01 04 be 01 00 00 8d 2c 3b 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}