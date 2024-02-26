
rule Trojan_BAT_SmokeLoader_RDR_MTB{
	meta:
		description = "Trojan:BAT/SmokeLoader.RDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {28 2f 00 00 0a 6f 30 00 00 0a 1f 0a 0d 11 04 6f 31 00 00 0a 13 05 1f 0b 0d 11 05 02 16 02 8e 69 } //00 00 
	condition:
		any of ($a_*)
 
}