
rule TrojanSpy_Win32_Rebhip_G{
	meta:
		description = "TrojanSpy:Win32/Rebhip.G,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 6e 69 74 43 6f 6d 61 6e 64 6f 73 } //01 00  UnitComandos
		$a_03_1 = {5c 53 70 79 2d 4e 65 74 20 5b 52 41 54 5d 20 90 02 08 5c 53 65 72 76 65 72 5c 50 6c 75 67 69 6e 44 6c 6c 90 00 } //01 00 
		$a_01_2 = {66 69 6c 65 6d 61 6e 61 67 65 72 7c 74 68 75 6d 62 70 72 6f 67 72 65 73 73 7c 00 } //01 00 
		$a_01_3 = {63 61 6d 73 70 79 00 } //01 00 
		$a_01_4 = {74 68 75 6d 62 6e 61 69 6c 7c 58 58 58 7c 00 } //00 00 
		$a_00_5 = {5d 04 00 } //00 47 
	condition:
		any of ($a_*)
 
}