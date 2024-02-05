
rule Trojan_Win32_Delfiles_Q{
	meta:
		description = "Trojan:Win32/Delfiles.Q,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 03 00 "
		
	strings :
		$a_01_0 = {64 65 6c 20 43 3a 5c 2a 2e 2a 2f 66 2f 73 2f 71 } //02 00 
		$a_01_1 = {73 68 75 74 64 6f 77 6e 20 2d 72 20 2d 74 20 36 30 30 20 2d 63 20 22 4f 70 66 65 72 22 } //02 00 
		$a_01_2 = {53 74 75 78 6e 65 74 20 43 6c 65 61 6e 65 72 2e 62 61 74 } //01 00 
		$a_01_3 = {61 73 73 6f 63 20 2e } //01 00 
		$a_01_4 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 74 20 2f 69 6d } //00 00 
	condition:
		any of ($a_*)
 
}