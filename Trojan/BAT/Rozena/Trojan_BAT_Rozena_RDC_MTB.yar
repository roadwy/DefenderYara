
rule Trojan_BAT_Rozena_RDC_MTB{
	meta:
		description = "Trojan:BAT/Rozena.RDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {07 11 04 07 11 04 91 20 ff 00 00 00 61 1f 11 58 d2 9c 11 04 17 58 13 04 11 04 07 8e 69 } //00 00 
	condition:
		any of ($a_*)
 
}