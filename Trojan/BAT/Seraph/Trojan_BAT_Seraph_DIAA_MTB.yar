
rule Trojan_BAT_Seraph_DIAA_MTB{
	meta:
		description = "Trojan:BAT/Seraph.DIAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_01_0 = {11 04 11 05 58 13 04 11 05 17 58 13 05 11 05 02 31 ee } //01 00 
		$a_01_1 = {52 65 76 65 72 73 65 } //00 00  Reverse
	condition:
		any of ($a_*)
 
}