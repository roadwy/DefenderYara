
rule TrojanSpy_Win32_Vundo_A{
	meta:
		description = "TrojanSpy:Win32/Vundo.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 48 04 c7 00 64 74 72 52 89 50 08 a3 } //01 00 
		$a_01_1 = {74 70 66 81 7e 1c 44 65 74 68 } //01 00 
		$a_01_2 = {66 c7 46 1c 44 65 66 c7 46 1e 74 6f 66 c7 46 20 75 72 66 c7 46 22 73 21 } //00 00 
	condition:
		any of ($a_*)
 
}