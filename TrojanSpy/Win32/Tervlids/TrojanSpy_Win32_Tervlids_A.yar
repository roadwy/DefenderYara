
rule TrojanSpy_Win32_Tervlids_A{
	meta:
		description = "TrojanSpy:Win32/Tervlids.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {6a 10 ff d7 6a 14 8b f0 ff d7 81 e6 00 80 00 00 68 90 00 00 00 81 fe 00 80 00 00 0f 94 c3 24 01 3c 01 0f 94 44 24 13 ff d7 24 01 3c 01 8b 44 24 14 0f 94 c1 83 f8 30 7c 57 } //01 00 
		$a_01_1 = {5f 6e 74 73 6c 6f 67 2e 64 61 74 00 } //01 00 
		$a_01_2 = {3c 3c 25 73 3e 3e 5b 00 } //00 00  㰼猥㸾[
	condition:
		any of ($a_*)
 
}