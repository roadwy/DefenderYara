
rule Trojan_BAT_Keylogger_ABEK_MTB{
	meta:
		description = "Trojan:BAT/Keylogger.ABEK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {16 fe 01 13 07 11 07 2d 31 00 28 90 01 03 0a 13 04 02 7b 90 01 03 04 72 90 01 03 70 02 7b 90 01 03 04 72 90 01 03 70 28 90 01 03 0a 13 05 11 04 11 05 17 28 90 01 03 0a 00 00 02 02 7b 90 01 03 04 72 90 01 03 70 17 8d 90 01 03 01 13 06 11 06 16 1f 7c 9d 11 06 6f 90 01 03 0a 16 9a 73 90 01 03 06 7d 90 01 03 04 00 de 05 90 00 } //01 00 
		$a_01_1 = {6d 00 73 00 6f 00 6b 00 6c 00 6f 00 67 00 73 00 } //01 00  msoklogs
		$a_01_2 = {6d 00 73 00 6f 00 6b 00 6c 00 6f 00 67 00 73 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //00 00  msoklogs.Properties.Resources
	condition:
		any of ($a_*)
 
}