
rule TrojanSpy_Win32_Talsab_B{
	meta:
		description = "TrojanSpy:Win32/Talsab.B,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {b8 68 58 4d 56 bb 00 00 00 00 b9 0a 00 00 00 ba 58 56 00 00 ed 81 fb 68 58 4d 56 0f 94 45 ff } //01 00 
		$a_01_1 = {61 76 70 2e 65 78 65 } //01 00 
		$a_01_2 = {5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 20 46 6f 6c 64 65 72 73 } //02 00 
		$a_01_3 = {73 69 66 72 65 6c 69 32 } //00 00 
	condition:
		any of ($a_*)
 
}