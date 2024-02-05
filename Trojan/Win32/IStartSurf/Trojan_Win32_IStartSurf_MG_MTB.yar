
rule Trojan_Win32_IStartSurf_MG_MTB{
	meta:
		description = "Trojan:Win32/IStartSurf.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 c1 89 04 8a 41 81 f9 90 01 04 7c 90 09 11 00 8b 44 8a 90 01 01 c1 e8 90 01 01 33 44 8a 90 01 01 69 c0 90 00 } //01 00 
		$a_02_1 = {33 0c ba 81 e1 90 01 04 33 0c ba 8b c1 d1 e9 83 e0 90 01 01 69 c0 90 01 04 33 c1 33 84 ba 90 01 04 89 04 ba 47 3b fe 7c 90 09 04 00 8b 4c ba 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}