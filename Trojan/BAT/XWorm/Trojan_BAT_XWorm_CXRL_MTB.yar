
rule Trojan_BAT_XWorm_CXRL_MTB{
	meta:
		description = "Trojan:BAT/XWorm.CXRL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {72 01 01 00 70 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 90 02 05 06 18 6f 90 01 01 00 00 0a 06 6f 90 01 01 00 00 0a 13 04 02 0d 11 04 09 16 09 8e b7 6f 90 01 01 00 00 0a 0b de 11 de 0f 25 28 90 01 01 00 00 0a 13 05 28 90 01 01 00 00 0a de 00 07 90 00 } //01 00 
		$a_01_1 = {35 00 78 00 61 00 44 00 4c 00 68 00 4e 00 41 00 34 00 78 00 72 00 37 00 54 00 6f 00 63 00 77 00 7a 00 } //00 00  5xaDLhNA4xr7Tocwz
	condition:
		any of ($a_*)
 
}