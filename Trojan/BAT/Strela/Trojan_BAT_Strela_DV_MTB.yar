
rule Trojan_BAT_Strela_DV_MTB{
	meta:
		description = "Trojan:BAT/Strela.DV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 17 58 08 5d 0b 02 7b 0a 00 00 04 06 90 01 05 0d 02 7b 0a 00 00 04 07 90 01 05 13 04 11 05 09 7b 08 00 00 04 11 04 7b 09 00 00 04 5a 11 04 7b 08 00 00 04 09 7b 09 00 00 04 5a 59 58 13 05 06 17 58 0a 06 08 32 b5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}