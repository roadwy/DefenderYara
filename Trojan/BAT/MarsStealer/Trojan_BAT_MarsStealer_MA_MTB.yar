
rule Trojan_BAT_MarsStealer_MA_MTB{
	meta:
		description = "Trojan:BAT/MarsStealer.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 11 05 16 11 06 6f 90 01 03 0a 00 00 09 11 05 16 11 04 6f 90 01 03 0a 25 13 06 16 fe 03 13 08 11 08 2d db 90 00 } //01 00 
		$a_03_1 = {13 05 16 13 06 73 90 01 03 0a 13 07 11 07 6f 90 01 03 0a 16 2d d3 90 00 } //01 00 
		$a_01_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 36 00 32 00 2e 00 32 00 30 00 34 00 2e 00 34 00 31 00 2e 00 36 00 39 00 } //01 00  http://62.204.41.69
		$a_01_3 = {49 6e 76 6f 6b 65 } //01 00  Invoke
		$a_01_4 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //01 00  MemoryStream
		$a_01_5 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggableAttribute
	condition:
		any of ($a_*)
 
}