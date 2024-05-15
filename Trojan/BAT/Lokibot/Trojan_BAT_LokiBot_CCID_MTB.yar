
rule Trojan_BAT_LokiBot_CCID_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.CCID!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {07 08 07 08 91 11 04 08 1f 16 5d 91 61 07 11 } //00 00 
	condition:
		any of ($a_*)
 
}