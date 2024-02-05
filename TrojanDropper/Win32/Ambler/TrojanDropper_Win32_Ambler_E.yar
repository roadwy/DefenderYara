
rule TrojanDropper_Win32_Ambler_E{
	meta:
		description = "TrojanDropper:Win32/Ambler.E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {83 c4 04 50 68 f5 01 00 00 6a 00 ff 15 90 01 04 8b f0 85 f6 0f 84 90 01 04 56 6a 00 ff 15 90 00 } //01 00 
		$a_03_1 = {88 06 0f be 43 01 0f be 4c 2f 01 50 51 e8 90 01 04 88 46 01 0f be 53 02 0f be 44 2f 02 52 50 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}