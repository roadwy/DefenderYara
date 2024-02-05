
rule Trojan_BAT_PowDow_NEAB_MTB{
	meta:
		description = "Trojan:BAT/PowDow.NEAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {02 28 06 00 00 06 74 1e 00 00 01 72 51 00 00 70 20 00 01 00 00 14 14 14 6f 1b 00 00 0a 2a } //02 00 
		$a_01_1 = {69 00 73 00 20 00 74 00 61 00 6d 00 70 00 65 00 72 00 65 00 64 00 } //02 00 
		$a_01_2 = {73 65 74 5f 43 72 65 61 74 65 4e 6f 57 69 6e 64 6f 77 } //00 00 
	condition:
		any of ($a_*)
 
}