
rule Trojan_BAT_Crypter_X_MTB{
	meta:
		description = "Trojan:BAT/Crypter.X!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {07 00 00 11 00 28 90 01 01 00 00 0a 7e 03 00 00 04 28 18 00 00 06 74 01 00 00 1b 0a 28 17 00 00 06 26 28 16 00 00 06 16 fe 01 0d 09 2d 02 16 0b 16 0b 2b 90 01 01 00 02 07 8f 90 01 01 00 00 01 25 71 90 01 01 00 00 01 06 07 00 90 00 } //02 00 
		$a_00_1 = {58 65 67 65 72 } //02 00  Xeger
		$a_00_2 = {46 61 72 65 } //00 00  Fare
		$a_00_3 = {5d 04 00 00 84 } //35 04 
	condition:
		any of ($a_*)
 
}