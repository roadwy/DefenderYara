
rule TrojanSpy_Win32_Sparsay_gen_A{
	meta:
		description = "TrojanSpy:Win32/Sparsay.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {64 65 73 63 62 6c 6f 6b } //02 00  descblok
		$a_01_1 = {5f 32 73 79 73 2e 70 68 70 3f 50 41 52 30 3d } //01 00  _2sys.php?PAR0=
		$a_01_2 = {77 65 62 63 72 79 70 74 2e 64 6c 6c 00 } //01 00 
		$a_01_3 = {64 6d 6c 2e 65 78 65 00 } //01 00 
		$a_01_4 = {6d 73 68 65 6c 70 2e 65 78 65 00 } //01 00 
		$a_01_5 = {73 71 6c 61 2e 64 6c 6c 00 } //00 00 
	condition:
		any of ($a_*)
 
}