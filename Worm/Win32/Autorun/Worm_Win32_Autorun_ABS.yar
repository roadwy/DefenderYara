
rule Worm_Win32_Autorun_ABS{
	meta:
		description = "Worm:Win32/Autorun.ABS,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {66 69 6c 65 20 74 6f 90 02 04 20 72 6f 6d 6f 74 65 90 00 } //01 00 
		$a_01_1 = {50 32 50 43 4d 44 2e 68 65 6c 6c 6f 21 } //01 00 
		$a_01_2 = {50 32 50 43 4d 44 2e 42 72 63 61 73 74 } //01 00 
		$a_01_3 = {6e 65 74 77 61 72 65 20 77 6f 72 6b 20 } //00 00 
	condition:
		any of ($a_*)
 
}