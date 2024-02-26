
rule Trojan_BAT_DCRat_RDL_MTB{
	meta:
		description = "Trojan:BAT/DCRat.RDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 6f 72 74 6e 69 74 65 5f 6c 6f 61 64 65 72 } //01 00  fortnite_loader
		$a_01_1 = {66 6e 5f 6c 6f 61 64 65 72 } //01 00  fn_loader
		$a_01_2 = {41 70 70 6c 65 43 68 65 61 74 73 } //00 00  AppleCheats
	condition:
		any of ($a_*)
 
}