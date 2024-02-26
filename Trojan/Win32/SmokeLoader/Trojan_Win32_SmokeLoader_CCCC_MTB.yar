
rule Trojan_Win32_SmokeLoader_CCCC_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.CCCC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b d0 8b c8 c1 ea 90 01 01 03 54 24 90 01 01 c1 e1 90 01 01 03 4c 90 01 01 24 03 c3 33 d1 33 d0 2b f2 8b ce 90 00 } //01 00 
		$a_03_1 = {8b c6 c1 e8 90 01 01 03 c5 33 c7 31 44 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}