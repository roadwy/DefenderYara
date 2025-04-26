
rule Worm_Win32_Spurtky_A{
	meta:
		description = "Worm:Win32/Spurtky.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {54 75 72 6b 2d 53 70 79 } //1 Turk-Spy
		$a_01_1 = {6b 75 72 62 61 6e 5f 69 73 69 6d } //1 kurban_isim
		$a_01_2 = {6d 73 6e 70 77 64 73 } //1 msnpwds
		$a_01_3 = {43 49 45 37 50 61 73 73 77 6f 72 64 73 } //1 CIE7Passwords
		$a_01_4 = {49 73 49 6e 53 61 6e 64 62 6f 78 65 73 } //1 IsInSandboxes
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}