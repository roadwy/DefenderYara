
rule Trojan_BAT_LokiBot_CCIE_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.CCIE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {5d 91 61 07 08 17 58 11 90 01 01 5d 91 59 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}