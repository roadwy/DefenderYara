
rule TrojanSpy_Win32_Aibatook_A{
	meta:
		description = "TrojanSpy:Win32/Aibatook.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {61 69 6b 6f 74 6f 62 61 90 02 10 6c 6f 67 69 6e 50 61 73 73 77 6f 72 64 90 00 } //02 00 
		$a_02_1 = {3f 43 61 72 64 4e 75 6d 3d 90 02 60 26 4c 6f 67 69 6e 50 61 73 73 3d 90 02 10 26 50 61 79 50 61 73 73 3d 90 00 } //01 00 
		$a_02_2 = {3f 4d 41 43 3d 90 02 10 26 56 45 52 3d 90 00 } //00 00 
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}