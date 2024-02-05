
rule Trojan_BAT_Seraph_PSKC_MTB{
	meta:
		description = "Trojan:BAT/Seraph.PSKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {28 0f 00 00 06 0a 28 0e 00 00 0a 06 6f 0f 00 00 0a 28 07 00 00 06 74 02 00 00 1b 28 06 00 00 06 0b dd 03 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}