
rule Backdoor_Win32_WarzoneRAT_GA_MTB{
	meta:
		description = "Backdoor:Win32/WarzoneRAT.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_80_0 = {5c 57 37 48 36 34 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 52 69 6e 67 33 20 43 52 41 54 20 78 36 34 5c 52 69 6e 67 33 20 43 52 41 54 20 78 36 34 5c 6e 6f 70 65 2e 70 64 62 } //\W7H64\source\repos\Ring3 CRAT x64\Ring3 CRAT x64\nope.pdb  00 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_Win32_WarzoneRAT_GA_MTB_2{
	meta:
		description = "Backdoor:Win32/WarzoneRAT.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_80_0 = {77 61 72 7a 6f 6e 65 31 36 30 } //warzone160  01 00 
		$a_80_1 = {5b 45 4e 54 45 52 5d } //[ENTER]  01 00 
		$a_80_2 = {5b 42 4b 53 50 5d } //[BKSP]  01 00 
		$a_80_3 = {5b 54 41 42 5d } //[TAB]  01 00 
		$a_80_4 = {5b 43 54 52 4c 5d } //[CTRL]  01 00 
		$a_80_5 = {5b 41 4c 54 5d } //[ALT]  01 00 
		$a_80_6 = {5b 43 41 50 53 5d } //[CAPS]  01 00 
		$a_80_7 = {5b 45 53 43 5d } //[ESC]  01 00 
		$a_80_8 = {5b 49 4e 53 45 52 54 5d } //[INSERT]  01 00 
		$a_80_9 = {41 56 45 5f 4d 41 52 49 41 } //AVE_MARIA  00 00 
		$a_00_10 = {5d 04 00 00 22 65 04 80 } //5c 21 
	condition:
		any of ($a_*)
 
}