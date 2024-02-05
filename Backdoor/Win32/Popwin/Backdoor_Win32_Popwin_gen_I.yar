
rule Backdoor_Win32_Popwin_gen_I{
	meta:
		description = "Backdoor:Win32/Popwin.gen!I,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 09 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {6e 74 73 64 20 2d 63 20 71 20 2d 70 20 } //03 00 
		$a_01_1 = {74 72 6f 6a 64 69 65 } //01 00 
		$a_01_2 = {53 59 53 54 45 4d 5c 43 6f 6e 74 72 6f 6c 53 65 74 30 30 31 5c 43 6f 6e 74 72 6f 6c 5c 53 65 73 73 69 6f 6e 20 4d 61 6e 61 67 65 72 5c } //02 00 
		$a_01_3 = {52 41 56 54 49 4d 45 52 } //01 00 
		$a_01_4 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c } //02 00 
		$a_01_5 = {72 74 76 73 63 61 6e } //00 00 
	condition:
		any of ($a_*)
 
}