
rule TrojanClicker_Win32_Delf_gen_R{
	meta:
		description = "TrojanClicker:Win32/Delf.gen!R,SIGNATURE_TYPE_PEHSTR_EXT,2a 00 2a 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //10 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {73 65 61 72 63 68 2e 63 6f 6d 2f 6e 65 77 2e 70 68 70 } //10 search.com/new.php
		$a_01_2 = {68 74 74 70 3a 2f 2f 62 6c 61 63 6b 74 72 61 66 66 2e 63 6f 6d 2f 74 72 61 63 6b 2e 70 68 70 3f } //10 http://blacktraff.com/track.php?
		$a_01_3 = {68 00 61 00 72 00 64 00 70 00 6f 00 72 00 6e 00 6d 00 70 00 67 00 00 00 } //10
		$a_01_4 = {70 6c 61 79 65 72 2e 70 68 70 00 } //1
		$a_01_5 = {57 65 62 42 72 6f 77 73 65 72 31 42 65 66 6f 72 65 4e 61 76 69 67 61 74 65 32 } //1 WebBrowser1BeforeNavigate2
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=42
 
}