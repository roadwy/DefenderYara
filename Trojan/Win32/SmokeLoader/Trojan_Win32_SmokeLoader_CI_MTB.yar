
rule Trojan_Win32_SmokeLoader_CI_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.CI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 44 24 18 8b 44 24 18 89 44 24 20 8b 4c 24 1c 8b c6 d3 e8 8b 4c 24 10 03 44 24 34 89 44 24 14 33 44 24 20 33 c8 2b f9 8d 44 24 24 89 4c 24 10 89 7c 24 28 e8 [0-04] 83 eb 01 0f } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}