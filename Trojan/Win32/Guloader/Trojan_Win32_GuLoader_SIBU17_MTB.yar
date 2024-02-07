
rule Trojan_Win32_GuLoader_SIBU17_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SIBU17!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {75 6e 6b 6e 6f 77 6e 64 6c 6c 2e 70 64 62 } //01 00  unknowndll.pdb
		$a_03_1 = {ff 34 0f d9 90 01 04 90 02 6a 31 04 24 90 02 64 8f 04 0f 90 02 6c 83 c1 04 90 02 50 81 f9 90 01 04 90 02 40 0f 85 90 01 04 90 02 b0 ff d7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}