
rule Trojan_BAT_DCRat_RDH_MTB{
	meta:
		description = "Trojan:BAT/DCRat.RDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {07 02 16 02 8e 69 6f 28 00 00 0a 00 07 6f 29 00 00 0a 00 06 6f 2a 00 00 0a 0c } //00 00 
	condition:
		any of ($a_*)
 
}