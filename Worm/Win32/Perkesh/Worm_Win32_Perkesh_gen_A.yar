
rule Worm_Win32_Perkesh_gen_A{
	meta:
		description = "Worm:Win32/Perkesh.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {89 45 f4 68 c0 5d 00 71 8d 83 84 00 00 00 50 c6 45 0b 01 ff 15 74 50 00 71 50 ff 15 78 51 00 71 } //01 00 
		$a_00_1 = {45 78 70 6c 6f 69 74 00 52 45 53 } //01 00 
		$a_02_2 = {25 73 25 73 2e 69 6e 66 90 02 04 61 75 74 6f 72 75 6e 90 00 } //01 00 
		$a_00_3 = {25 73 5c 6f 70 65 6e 5c 25 73 20 25 73 2c 25 73 } //00 00  %s\open\%s %s,%s
	condition:
		any of ($a_*)
 
}