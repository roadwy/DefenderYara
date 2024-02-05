
rule Trojan_BAT_Bladabindi_DE_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {28 1a 00 00 0a 0a 06 28 1b 00 00 0a 0b 07 28 1c 00 00 0a 0c 08 6f 1d 00 00 0a 72 90 01 03 70 14 6f 1e 00 00 0a 26 20 10 27 00 00 28 1f 00 00 0a 00 14 0d 90 00 } //01 00 
		$a_03_1 = {28 23 00 00 0a 72 90 01 03 70 28 24 00 00 0a 09 28 25 00 00 0a 00 28 23 00 00 0a 72 90 01 03 70 28 24 00 00 0a 28 26 00 00 0a 26 28 27 00 00 0a 00 00 de 13 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}