
rule Trojan_BAT_AgentTesla_LCD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LCD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {09 11 04 11 05 6f 90 01 03 0a 13 08 09 11 04 11 05 6f 90 01 03 0a 13 09 11 09 28 90 01 03 0a 13 0a 08 07 11 0a d2 9c 00 11 05 17 58 13 05 90 00 } //01 00 
		$a_01_1 = {24 66 66 62 66 35 30 65 30 2d 66 36 61 63 2d 34 37 61 30 2d 38 32 63 37 2d 32 61 35 37 63 35 36 65 30 34 39 37 } //01 00  $ffbf50e0-f6ac-47a0-82c7-2a57c56e0497
		$a_01_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_3 = {7a 68 77 6c 57 69 6e 46 6f 72 6d 54 } //01 00  zhwlWinFormT
		$a_01_4 = {43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 } //01 00  ColorTranslator
		$a_01_5 = {47 65 74 50 69 78 65 6c } //01 00  GetPixel
		$a_01_6 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerNonUserCodeAttribute
	condition:
		any of ($a_*)
 
}