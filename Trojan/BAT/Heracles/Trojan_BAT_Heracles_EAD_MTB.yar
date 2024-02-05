
rule Trojan_BAT_Heracles_EAD_MTB{
	meta:
		description = "Trojan:BAT/Heracles.EAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {0b 2b 41 00 00 7e 19 00 00 04 0c 28 90 01 01 00 00 0a 08 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 0d 73 76 00 00 06 25 09 28 90 01 01 00 00 06 6f 90 01 01 00 00 06 00 0b de 10 25 28 90 01 01 00 00 0a 13 04 00 28 90 01 01 00 00 0a de 00 00 2b 05 17 13 05 2b ba 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}