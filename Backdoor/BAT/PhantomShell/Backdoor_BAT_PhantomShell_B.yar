
rule Backdoor_BAT_PhantomShell_B{
	meta:
		description = "Backdoor:BAT/PhantomShell.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 75 6d 61 6e 32 5f 61 73 70 78 90 19 01 09 61 2d 7a 41 2d 5a 30 2d 39 90 09 01 00 90 19 01 09 61 2d 7a 41 2d 5a 30 2d 39 90 00 } //01 00 
		$a_01_1 = {58 00 2d 00 73 00 69 00 4c 00 6f 00 63 00 6b 00 2d 00 43 00 6f 00 6d 00 6d 00 65 00 6e 00 74 00 } //01 00 
		$a_01_2 = {78 00 2d 00 73 00 69 00 4c 00 6f 00 63 00 6b 00 2d 00 53 00 74 00 65 00 70 00 31 00 } //01 00 
		$a_03_3 = {4d 4f 56 45 69 74 2e 44 4d 5a 2e 43 6f 72 65 2e 44 61 74 61 90 19 01 09 61 2d 7a 41 2d 5a 30 2d 39 90 09 01 00 90 19 01 09 61 2d 7a 41 2d 5a 30 2d 39 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}