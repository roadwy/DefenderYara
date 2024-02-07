
rule TrojanSpy_Win32_Banker_VDE_bit{
	meta:
		description = "TrojanSpy:Win32/Banker.VDE!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {30 10 c1 c2 07 40 49 75 f7 } //01 00 
		$a_03_1 = {8b d0 c6 05 90 01 04 57 c6 05 90 01 04 6f c6 05 90 01 04 77 c6 05 90 01 04 36 c6 05 90 01 04 34 c6 05 90 01 04 44 c6 05 90 01 04 69 c6 05 90 01 04 73 c6 05 90 01 04 61 c6 05 90 01 04 62 c6 05 90 01 04 6c c6 05 90 01 04 65 90 00 } //01 00 
		$a_01_2 = {8b c6 24 0f 3c 0a 1c 69 2f 88 04 11 c1 ee 04 49 79 ee } //00 00 
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}