
rule Trojan_BAT_Lazy_NLC_MTB{
	meta:
		description = "Trojan:BAT/Lazy.NLC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {7e 12 00 00 04 07 25 17 58 0b 91 1e 62 58 16 2d bf 7e 90 01 01 00 00 04 07 25 17 58 0b 91 58 16 2d e0 90 00 } //01 00 
		$a_01_1 = {46 00 69 00 6c 00 65 00 41 00 73 00 73 00 6f 00 63 00 69 00 61 00 74 00 69 00 6f 00 6e 00 } //00 00  FileAssociation
	condition:
		any of ($a_*)
 
}