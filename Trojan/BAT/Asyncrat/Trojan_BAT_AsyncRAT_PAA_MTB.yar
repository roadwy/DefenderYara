
rule Trojan_BAT_AsyncRAT_PAA_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {13 06 11 06 08 6f 90 01 03 0a 11 06 18 6f 90 01 03 0a 11 06 18 6f 90 01 03 0a 11 06 0d 09 6f 90 01 03 0a 13 04 11 04 06 16 06 8e 69 6f 90 01 03 0a 13 05 28 42 00 00 0a 11 05 6f 90 01 03 0a 13 07 de 14 09 2c 06 09 6f 90 01 03 0a dc 07 2c 06 07 6f 90 01 03 0a dc 11 07 2a 90 00 } //01 00 
		$a_03_1 = {72 f7 07 00 70 6f 90 01 03 0a 06 6f 90 01 03 0a 72 07 08 00 70 03 28 90 01 03 0a 6f 90 01 03 0a 06 6f 90 01 03 0a 26 14 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}