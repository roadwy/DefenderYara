
rule Worm_Win32_Wangy_gen_C{
	meta:
		description = "Worm:Win32/Wangy.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0b 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 77 77 77 2e 30 31 73 6f 73 2e 63 6f 6d } //01 00 
		$a_01_1 = {68 79 32 30 31 30 61 } //01 00 
		$a_01_2 = {44 65 6c 65 74 65 4d 65 2e 62 61 74 } //0a 00 
		$a_00_3 = {65 78 69 73 74 20 22 00 22 20 67 6f 74 6f 20 74 72 79 00 64 65 6c 20 25 30 00 00 69 6e 74 66 20 } //00 00 
	condition:
		any of ($a_*)
 
}