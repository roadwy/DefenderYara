
rule Trojan_BAT_Quasar_NAQ_MTB{
	meta:
		description = "Trojan:BAT/Quasar.NAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {28 10 00 00 0a 72 90 01 02 00 70 02 73 90 01 02 00 0a 28 90 01 02 00 0a 28 90 01 02 00 0a 28 90 01 02 00 0a 06 02 6f 90 01 02 00 0a 0b 25 07 28 90 01 02 00 0a 28 90 01 02 00 0a 26 90 00 } //01 00 
		$a_01_1 = {61 00 6c 00 6b 00 61 00 6c 00 75 00 72 00 6f 00 70 00 73 00 2e 00 73 00 62 00 73 00 } //00 00  alkalurops.sbs
	condition:
		any of ($a_*)
 
}