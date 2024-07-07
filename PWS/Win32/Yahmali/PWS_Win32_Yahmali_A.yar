
rule PWS_Win32_Yahmali_A{
	meta:
		description = "PWS:Win32/Yahmali.A,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 07 00 00 "
		
	strings :
		$a_01_0 = {2d 43 61 70 73 20 4c 6f 63 6b 2d } //2 -Caps Lock-
		$a_01_1 = {2d 42 61 63 6b 2d } //1 -Back-
		$a_01_2 = {53 49 47 4e 20 49 4e } //1 SIGN IN
		$a_01_3 = {59 61 68 6f 6f 21 20 4d 65 73 73 65 6e 67 65 72 } //2 Yahoo! Messenger
		$a_01_4 = {69 6e 64 65 78 2e 70 68 70 3f 74 65 78 74 3d } //2 index.php?text=
		$a_01_5 = {44 55 49 56 69 65 77 57 6e 64 43 6c 61 73 73 4e 61 6d 65 } //1 DUIViewWndClassName
		$a_01_6 = {66 3d 00 80 74 0d 6a 10 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*2) >=10
 
}