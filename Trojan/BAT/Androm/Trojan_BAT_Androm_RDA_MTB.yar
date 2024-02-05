
rule Trojan_BAT_Androm_RDA_MTB{
	meta:
		description = "Trojan:BAT/Androm.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {16 07 a2 6f a6 00 00 0a 75 27 00 00 01 13 04 11 04 72 90 01 04 6f a7 00 00 0a 7e 56 00 00 04 13 0b 11 0b 28 a8 00 00 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}