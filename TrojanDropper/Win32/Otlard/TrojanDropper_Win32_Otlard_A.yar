
rule TrojanDropper_Win32_Otlard_A{
	meta:
		description = "TrojanDropper:Win32/Otlard.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {bb 85 00 00 00 88 84 0d 90 01 04 8b c6 99 f7 fb 41 8a c2 b2 03 f6 ea 90 00 } //01 00 
		$a_01_1 = {6a 01 6a 01 bb ff 01 0f 00 53 } //01 00 
		$a_01_2 = {25 63 25 63 25 63 25 30 34 78 } //00 00  %c%c%c%04x
	condition:
		any of ($a_*)
 
}