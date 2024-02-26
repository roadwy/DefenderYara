
rule Trojan_BAT_Clicker_SPQE_MTB{
	meta:
		description = "Trojan:BAT/Clicker.SPQE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_81_0 = {4b 68 65 69 6f 74 72 6a } //01 00  Kheiotrj
		$a_81_1 = {42 73 76 71 76 64 } //01 00  Bsvqvd
		$a_81_2 = {4f 69 6b 6f 68 65 72 67 } //00 00  Oikoherg
	condition:
		any of ($a_*)
 
}