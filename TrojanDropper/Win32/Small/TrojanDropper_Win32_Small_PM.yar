
rule TrojanDropper_Win32_Small_PM{
	meta:
		description = "TrojanDropper:Win32/Small.PM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {32 33 20 2d 20 36 36 36 00 } //01 00 
		$a_03_1 = {b8 01 00 00 00 85 c0 74 30 6a 0a ff 15 90 01 04 68 90 01 04 6a 00 ff 15 90 01 04 89 45 fc 90 00 } //01 00 
		$a_03_2 = {8b 55 08 03 55 fc 8a 02 2c 90 01 01 8b 4d 08 03 4d fc 88 01 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}