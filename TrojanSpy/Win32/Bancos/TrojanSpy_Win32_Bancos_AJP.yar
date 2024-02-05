
rule TrojanSpy_Win32_Bancos_AJP{
	meta:
		description = "TrojanSpy:Win32/Bancos.AJP,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {4a 61 6e 65 6c 61 50 61 69 43 6f 6e 74 61 69 6e 65 72 49 54 41 } //02 00 
		$a_01_1 = {63 72 79 70 74 61 74 69 6f 6e } //02 00 
		$a_01_2 = {54 00 46 00 41 00 4a 00 55 00 44 00 41 00 } //02 00 
		$a_01_3 = {6d 00 61 00 6e 00 64 00 61 00 2e 00 70 00 68 00 70 00 } //03 00 
		$a_01_4 = {74 6d 31 54 69 6d 65 72 } //02 00 
		$a_01_5 = {8b 45 f4 8b 17 0f b7 74 5a fe 8b 55 f8 0f b7 44 42 fe 66 33 f0 0f b7 f6 85 f6 75 07 } //00 00 
		$a_00_6 = {5d 04 00 00 44 06 } //03 80 
	condition:
		any of ($a_*)
 
}