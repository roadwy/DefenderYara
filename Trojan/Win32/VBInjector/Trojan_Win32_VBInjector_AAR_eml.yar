
rule Trojan_Win32_VBInjector_AAR_eml{
	meta:
		description = "Trojan:Win32/VBInjector.AAR!eml,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {83 c4 10 68 90 01 04 68 90 1b 00 68 90 1b 00 68 90 1b 00 83 c4 10 90 0a 2d 00 68 90 1b 00 68 90 1b 00 68 90 1b 00 68 90 02 1f 81 90 00 } //05 00 
		$a_00_1 = {43 00 4f 00 6e 00 74 00 72 00 6f 00 72 00 61 00 58 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_03_2 = {5f 31 f2 68 90 01 04 68 90 1b 00 68 90 1b 00 68 90 1b 00 83 c4 10 51 81 90 00 } //01 00 
		$a_03_3 = {5a 4b 52 81 ca 90 01 04 5a eb 90 0a 11 00 52 81 ca 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}