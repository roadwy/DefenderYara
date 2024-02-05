
rule TrojanDropper_Win32_Rustock_J{
	meta:
		description = "TrojanDropper:Win32/Rustock.J,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_07_0 = {00 e8 03 00 00 00 33 c0 c3 90 17 04 01 01 01 01 60 e9 eb 68 90 00 } //01 00 
		$a_07_1 = {e8 09 00 00 00 33 c0 83 c4 44 c3 90 02 04 90 17 03 01 01 01 60 eb 68 90 00 } //01 00 
		$a_01_2 = {e8 91 fc ff ff 85 c0 74 05 33 f6 46 eb 13 68 90 01 04 53 e8 7d fc ff ff 8b f0 f7 de 1b f6 f7 de 83 7d 08 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}