
rule Trojan_BAT_Heracles_GKAA_MTB{
	meta:
		description = "Trojan:BAT/Heracles.GKAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {1e 13 08 38 90 01 01 ff ff ff 08 74 90 01 01 00 00 01 03 6f 90 01 01 00 00 0a 08 74 90 01 01 00 00 01 6f 90 01 01 00 00 0a 13 04 90 00 } //02 00 
		$a_03_1 = {01 02 16 02 8e 69 6f 90 01 01 00 00 0a de 49 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}