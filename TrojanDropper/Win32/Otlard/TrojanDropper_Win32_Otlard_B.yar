
rule TrojanDropper_Win32_Otlard_B{
	meta:
		description = "TrojanDropper:Win32/Otlard.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {b9 85 00 00 00 88 84 35 90 01 04 8b c3 99 f7 f9 b1 03 46 8a c2 f6 e9 90 00 } //01 00 
		$a_01_1 = {6a 01 6a 01 68 ff 01 0f 00 56 } //01 00 
		$a_01_2 = {40 f7 45 fc 00 80 00 00 74 02 } //00 00 
	condition:
		any of ($a_*)
 
}