
rule Trojan_BAT_Wagex_SPDU_MTB{
	meta:
		description = "Trojan:BAT/Wagex.SPDU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {11 04 09 17 73 90 01 03 0a 13 05 11 05 02 16 02 8e 69 6f 90 01 03 0a 11 04 6f 90 01 03 0a 13 06 dd 2b 00 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}