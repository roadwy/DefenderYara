
rule Backdoor_Win32_WarzoneRAT_GB_MTB{
	meta:
		description = "Backdoor:Win32/WarzoneRAT.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_80_0 = {77 61 72 7a 6f 6e 65 54 55 52 42 4f } //warzoneTURBO  1
		$a_80_1 = {5b 45 4e 54 45 52 5d } //[ENTER]  1
		$a_80_2 = {5b 42 4b 53 50 5d } //[BKSP]  1
		$a_80_3 = {5b 54 41 42 5d } //[TAB]  1
		$a_80_4 = {5b 43 54 52 4c 5d } //[CTRL]  1
		$a_80_5 = {5b 41 4c 54 5d } //[ALT]  1
		$a_80_6 = {5b 43 41 50 53 5d } //[CAPS]  1
		$a_80_7 = {5b 45 53 43 5d } //[ESC]  1
		$a_80_8 = {5b 49 4e 53 45 52 54 5d } //[INSERT]  1
		$a_80_9 = {41 56 45 5f 4d 41 52 49 41 } //AVE_MARIA  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1) >=10
 
}