
rule TrojanSpy_Win32_Banker_AGD{
	meta:
		description = "TrojanSpy:Win32/Banker.AGD,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 07 00 00 02 00 "
		
	strings :
		$a_01_0 = {4d 73 6e 54 75 63 6b } //02 00  MsnTuck
		$a_01_1 = {73 69 67 6e 69 6e 5f 73 75 62 6d 69 74 } //02 00  signin_submit
		$a_01_2 = {54 69 6d 65 72 32 54 69 6d 65 72 } //02 00  Timer2Timer
		$a_01_3 = {56 50 72 69 6e 63 69 70 61 6c } //03 00  VPrincipal
		$a_01_4 = {3f 6f 63 69 64 3d 68 6d 6c 6f 67 6f 75 74 } //03 00  ?ocid=hmlogout
		$a_01_5 = {65 64 74 53 65 6e 68 61 6c } //03 00  edtSenhal
		$a_01_6 = {67 61 69 61 5f 6c 6f 67 69 6e 66 6f 72 6d } //00 00  gaia_loginform
		$a_00_7 = {5d 04 00 00 c9 a0 02 80 5c 1c } //00 00 
	condition:
		any of ($a_*)
 
}