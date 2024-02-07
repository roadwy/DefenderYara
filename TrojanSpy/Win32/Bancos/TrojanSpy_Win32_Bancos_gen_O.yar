
rule TrojanSpy_Win32_Bancos_gen_O{
	meta:
		description = "TrojanSpy:Win32/Bancos.gen!O,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 07 00 00 02 00 "
		
	strings :
		$a_01_0 = {43 50 6c 41 70 70 6c 65 74 } //02 00  CPlApplet
		$a_00_1 = {2f 2f 3a 70 74 74 68 00 } //02 00  ⼯瀺瑴h
		$a_00_2 = {5c 73 77 6f 64 6e 69 77 5c 3a 63 } //02 00  \swodniw\:c
		$a_00_3 = {73 6f 76 69 75 71 72 41 5c 3a 43 } //01 00  soviuqrA\:C
		$a_00_4 = {70 69 7a 2e } //01 00  piz.
		$a_00_5 = {65 78 65 2e } //01 00  exe.
		$a_01_6 = {50 52 4f 46 45 53 53 49 4f 4e 41 4c } //00 00  PROFESSIONAL
	condition:
		any of ($a_*)
 
}