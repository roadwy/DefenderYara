
rule Worm_Win32_Vobfus_gen_W{
	meta:
		description = "Worm:Win32/Vobfus.gen!W,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {f5 01 00 00 00 1b 90 01 01 00 94 08 00 90 01 02 f5 02 00 00 80 59 90 01 01 ff 0a 90 01 02 10 00 90 00 } //01 00 
		$a_03_1 = {fb 12 fc 0d 6c 90 01 02 80 90 01 02 fc a0 90 00 } //01 00 
		$a_03_2 = {e7 aa f5 00 01 00 00 c2 90 09 07 00 4a c2 6c 90 01 01 ff fc 90 90 90 00 } //01 00 
		$a_01_3 = {00 56 42 2e 54 69 6d 65 72 00 } //01 00  嘀⹂楔敭r
		$a_01_4 = {00 56 42 2e 44 69 72 4c 69 73 74 42 6f 78 00 } //01 00 
		$a_01_5 = {00 00 4e 00 6f 00 41 00 75 00 74 00 6f 00 55 00 70 00 64 00 61 00 74 00 65 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}