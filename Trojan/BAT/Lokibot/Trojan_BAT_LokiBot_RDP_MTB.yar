
rule Trojan_BAT_LokiBot_RDP_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.RDP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {6f 17 00 00 0a 02 0e 07 0e 04 8e 69 6f 18 00 00 0a 0a 06 0b } //00 00 
	condition:
		any of ($a_*)
 
}