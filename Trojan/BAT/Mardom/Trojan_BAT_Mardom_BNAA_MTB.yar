
rule Trojan_BAT_Mardom_BNAA_MTB{
	meta:
		description = "Trojan:BAT/Mardom.BNAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_01_0 = {04 03 04 58 11 01 58 } //01 00 
		$a_01_1 = {52 65 76 65 72 73 65 } //00 00  Reverse
	condition:
		any of ($a_*)
 
}