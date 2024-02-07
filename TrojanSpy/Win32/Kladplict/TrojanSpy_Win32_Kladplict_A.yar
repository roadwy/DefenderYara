
rule TrojanSpy_Win32_Kladplict_A{
	meta:
		description = "TrojanSpy:Win32/Kladplict.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f 57 c0 0f 11 45 ea c7 45 fa 00 00 00 00 6a 0c 66 c7 45 fe 00 00 89 45 f0 89 45 fc 8d 45 e8 6a 02 50 c7 45 e8 01 00 06 00 c7 45 ec 00 01 00 00 c7 45 f4 01 00 02 00 c7 45 f8 00 01 00 00 ff 15 } //01 00 
		$a_01_1 = {5b 63 6c 69 70 62 6f 61 72 64 20 62 65 67 69 6e 5d } //01 00  [clipboard begin]
		$a_01_2 = {6b 00 6c 00 2e 00 64 00 61 00 74 00 } //01 00  kl.dat
		$a_01_3 = {4d 61 69 6e 20 52 65 74 75 72 6e 65 64 2e } //00 00  Main Returned.
		$a_00_4 = {5d 04 00 } //00 a6 
	condition:
		any of ($a_*)
 
}