
rule BrowserModifier_Win32_FreeScratchAndWin{
	meta:
		description = "BrowserModifier:Win32/FreeScratchAndWin,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {46 53 43 5c 46 53 43 43 6c 69 65 6e 74 } //3 FSC\FSCClient
		$a_01_1 = {25 73 5c 66 73 63 2e 69 6e 69 } //3 %s\fsc.ini
		$a_03_2 = {75 72 6c 5f 74 65 72 6d 73 90 02 06 75 72 6c 5f 66 69 6c 65 73 90 02 06 75 72 6c 5f 61 64 73 65 72 76 90 02 06 75 72 6c 5f 72 6f 6f 74 90 02 06 66 69 6c 65 6c 69 73 74 90 00 } //2
		$a_01_3 = {46 72 65 65 20 53 63 72 61 74 63 68 20 43 61 72 64 73 21 } //1 Free Scratch Cards!
		$a_01_4 = {66 72 65 65 2d 73 63 72 61 74 63 68 2d 63 61 72 64 73 2e 63 6f 6d } //1 free-scratch-cards.com
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}