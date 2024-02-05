
rule TrojanDropper_Win32_Unhjeca_A{
	meta:
		description = "TrojanDropper:Win32/Unhjeca.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 48 08 88 50 0c 33 c0 85 f6 7e 09 80 34 38 2a 40 3b c6 7c f7 } //01 00 
		$a_01_1 = {6a 61 76 61 20 2d 6a 61 72 20 00 } //00 00 
	condition:
		any of ($a_*)
 
}