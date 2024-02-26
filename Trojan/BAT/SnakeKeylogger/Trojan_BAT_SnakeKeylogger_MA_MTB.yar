
rule Trojan_BAT_SnakeKeylogger_MA_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {2b 0d 74 03 00 00 1b 2a 28 90 01 01 00 00 06 2b e7 6f 90 01 01 00 00 0a 2b ec 90 0a 25 00 2b 12 72 90 01 01 00 00 70 7e 90 01 01 00 00 04 90 00 } //02 00 
		$a_03_1 = {1e 2c 18 2b 18 2b 1d 2b 22 90 01 02 09 26 12 00 90 01 01 2d 07 26 de 2a 2b 1b 2b f4 2b 1a 2b f6 28 90 01 01 00 00 06 2b e1 28 0f 00 00 06 2b dc 28 10 00 00 06 2b d7 0a 2b e2 28 11 00 00 06 2b df 26 de 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_SnakeKeylogger_MA_MTB_2{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {57 d5 a2 fd 09 0f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 81 00 00 00 20 } //02 00 
		$a_01_1 = {42 75 69 6c 64 45 76 65 6e 74 2e 50 72 6f 70 65 72 74 69 65 73 } //02 00  BuildEvent.Properties
		$a_01_2 = {34 34 35 61 39 38 66 31 2d 35 62 66 64 2d 34 65 63 39 2d 61 66 33 64 2d 62 63 31 63 30 34 65 63 35 36 39 32 } //01 00  445a98f1-5bfd-4ec9-af3d-bc1c04ec5692
		$a_01_3 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_01_4 = {53 74 72 52 65 76 65 72 73 65 } //00 00  StrReverse
	condition:
		any of ($a_*)
 
}