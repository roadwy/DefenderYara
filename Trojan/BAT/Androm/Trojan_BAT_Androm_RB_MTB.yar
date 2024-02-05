
rule Trojan_BAT_Androm_RB_MTB{
	meta:
		description = "Trojan:BAT/Androm.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 07 9a 74 90 01 04 72 90 01 04 20 00 01 00 00 14 14 14 6f 90 01 03 0a 26 de 03 26 de 00 07 17 58 0b 07 06 8e 69 32 d5 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}