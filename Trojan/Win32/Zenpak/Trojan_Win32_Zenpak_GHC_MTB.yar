
rule Trojan_Win32_Zenpak_GHC_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GHC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c2 c1 e0 90 01 01 89 44 24 90 01 01 8b 44 24 90 01 01 01 44 24 90 01 01 8b 4c 24 90 01 01 8b c2 c1 e8 90 01 01 03 c3 03 ca 89 44 24 90 01 01 33 c8 8b 44 24 90 01 01 33 c1 c7 05 90 01 04 19 36 6b ff c7 05 90 01 08 89 44 24 90 01 01 2b f0 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}