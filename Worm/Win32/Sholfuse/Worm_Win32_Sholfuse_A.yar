
rule Worm_Win32_Sholfuse_A{
	meta:
		description = "Worm:Win32/Sholfuse.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 83 f9 41 76 0c 66 83 f9 5a 73 06 83 c1 20 66 89 08 83 c2 01 66 83 7c 54 04 00 8d 44 54 04 75 dc } //01 00 
		$a_03_1 = {50 68 f5 06 00 00 68 90 01 04 56 c7 44 24 20 00 00 00 00 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}