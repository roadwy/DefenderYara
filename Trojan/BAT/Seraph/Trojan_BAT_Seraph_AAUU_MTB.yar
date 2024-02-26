
rule Trojan_BAT_Seraph_AAUU_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AAUU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 77 65 66 6a 69 } //01 00  Fwefji
		$a_01_1 = {4d 68 65 75 72 66 67 } //01 00  Mheurfg
		$a_01_2 = {50 69 75 73 72 68 67 } //00 00  Piusrhg
	condition:
		any of ($a_*)
 
}