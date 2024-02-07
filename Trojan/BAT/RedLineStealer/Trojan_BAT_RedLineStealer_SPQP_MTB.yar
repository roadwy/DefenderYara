
rule Trojan_BAT_RedLineStealer_SPQP_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.SPQP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {13 0a 11 0a 6f 90 01 03 0a 72 01 00 00 70 28 90 01 03 0a 2c 14 11 0a 16 8c 28 00 00 01 14 6f 90 01 03 0a 26 dd 1b ff ff ff 12 09 28 90 01 03 0a 2d c7 90 00 } //01 00 
		$a_01_1 = {5a 00 75 00 65 00 6d 00 69 00 6c 00 68 00 71 00 68 00 79 00 6d 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //01 00  Zuemilhqhym.Properties.Resources
		$a_81_2 = {52 70 68 6b 6b 67 6d 78 63 74 69 66 6e 65 71 79 75 65 63 } //00 00  Rphkkgmxctifneqyuec
	condition:
		any of ($a_*)
 
}