
rule Trojan_BAT_NjRat_NEDS_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 02 00 00 04 00 "
		
	strings :
		$a_01_0 = {33 61 36 38 37 62 38 34 2d 38 38 38 64 2d 34 34 33 35 2d 39 66 65 62 2d 33 39 64 36 35 65 36 39 38 38 34 63 } //04 00  3a687b84-888d-4435-9feb-39d65e69884c
		$a_01_1 = {4f 62 66 75 73 63 61 74 65 64 5c 65 78 70 6c 6f 72 65 72 2e 70 64 62 } //00 00  Obfuscated\explorer.pdb
	condition:
		any of ($a_*)
 
}