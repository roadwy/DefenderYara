
rule TrojanSpy_Win32_Bancos_PR{
	meta:
		description = "TrojanSpy:Win32/Bancos.PR,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0b 00 0a 00 00 02 00 "
		
	strings :
		$a_01_0 = {74 78 5f 53 65 6e 43 61 72 74 00 } //02 00 
		$a_01_1 = {63 63 68 61 6d 61 72 44 61 64 6f 73 00 } //02 00 
		$a_01_2 = {64 65 66 69 6e 65 54 61 6d 61 6e 68 6f 00 } //02 00  敤楦敮慔慭桮o
		$a_01_3 = {62 75 74 61 6f 5f 43 6f 6e 66 69 72 6d 61 5f 00 } //02 00  畢慴彯潃普物慭_
		$a_00_4 = {53 00 65 00 6e 00 68 00 61 00 41 00 } //01 00  SenhaA
		$a_00_5 = {2d 00 3d 00 20 00 42 00 2d 00 72 00 2d 00 61 00 2d 00 64 00 2d 00 65 00 2d 00 73 00 2d 00 63 00 2d 00 6f 00 20 00 3d 00 2d 00 } //01 00  -= B-r-a-d-e-s-c-o =-
		$a_00_6 = {2d 00 3d 00 2d 00 20 00 42 00 2d 00 61 00 2d 00 6e 00 2d 00 65 00 2d 00 73 00 2d 00 65 00 20 00 2d 00 3d 00 2d 00 } //01 00  -=- B-a-n-e-s-e -=-
		$a_00_7 = {3d 00 2d 00 20 00 53 00 2d 00 61 00 2d 00 6e 00 2d 00 74 00 2d 00 61 00 2d 00 6e 00 2d 00 64 00 2d 00 65 00 2d 00 72 00 20 00 2d 00 3d 00 } //01 00  =- S-a-n-t-a-n-d-e-r -=
		$a_00_8 = {2d 00 3d 00 20 00 4d 00 2d 00 61 00 2d 00 73 00 2d 00 74 00 2d 00 65 00 2d 00 72 00 2d 00 63 00 2d 00 61 00 2d 00 72 00 2d 00 64 00 20 00 3d 00 2d 00 } //01 00  -= M-a-s-t-e-r-c-a-r-d =-
		$a_00_9 = {2d 00 3d 00 20 00 49 00 2d 00 6e 00 2d 00 66 00 2d 00 6f 00 2d 00 62 00 2d 00 75 00 2d 00 73 00 2d 00 63 00 2d 00 61 00 20 00 3d 00 2d 00 } //00 00  -= I-n-f-o-b-u-s-c-a =-
	condition:
		any of ($a_*)
 
}