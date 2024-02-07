
rule PWS_Win32_Yahmali_A{
	meta:
		description = "PWS:Win32/Yahmali.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 07 00 00 02 00 "
		
	strings :
		$a_01_0 = {2d 43 61 70 73 20 4c 6f 63 6b 2d } //01 00  -Caps Lock-
		$a_01_1 = {2d 42 61 63 6b 2d } //01 00  -Back-
		$a_01_2 = {53 49 47 4e 20 49 4e } //02 00  SIGN IN
		$a_01_3 = {59 61 68 6f 6f 21 20 4d 65 73 73 65 6e 67 65 72 } //02 00  Yahoo! Messenger
		$a_01_4 = {69 6e 64 65 78 2e 70 68 70 3f 74 65 78 74 3d } //01 00  index.php?text=
		$a_01_5 = {44 55 49 56 69 65 77 57 6e 64 43 6c 61 73 73 4e 61 6d 65 } //02 00  DUIViewWndClassName
		$a_01_6 = {66 3d 00 80 74 0d 6a 10 } //00 00 
	condition:
		any of ($a_*)
 
}