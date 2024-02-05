
rule TrojanDropper_Win32_Gamarue_G{
	meta:
		description = "TrojanDropper:Win32/Gamarue.G,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 0c 38 80 e9 42 32 ca ff 44 24 90 01 01 88 0c 38 39 5c 24 90 01 01 72 e7 90 00 } //01 00 
		$a_01_1 = {8a 08 40 3a cb 75 f9 2b c2 8b c8 0f 31 } //00 00 
	condition:
		any of ($a_*)
 
}