
rule Trojan_BAT_Quasar_NAP_MTB{
	meta:
		description = "Trojan:BAT/Quasar.NAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {28 10 00 00 0a 72 90 01 01 00 00 70 02 73 11 00 00 0a 28 90 01 01 00 00 0a 28 13 00 00 0a 28 90 01 01 00 00 0a 06 02 6f 90 01 01 00 00 0a 0b 25 07 28 90 01 01 00 00 0a 28 17 00 00 0a 90 00 } //01 00 
		$a_01_1 = {64 00 65 00 6f 00 6e 00 37 00 33 00 34 00 } //00 00  deon734
	condition:
		any of ($a_*)
 
}