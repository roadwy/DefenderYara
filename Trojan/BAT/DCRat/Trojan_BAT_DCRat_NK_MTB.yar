
rule Trojan_BAT_DCRat_NK_MTB{
	meta:
		description = "Trojan:BAT/DCRat.NK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {02 7b a4 02 00 04 03 04 61 20 ff 00 00 00 5f 95 03 1e 64 61 2a } //00 00 
	condition:
		any of ($a_*)
 
}