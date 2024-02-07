
rule Worm_Win32_Autorun_gen_AZ{
	meta:
		description = "Worm:Win32/Autorun.gen!AZ,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {25 73 41 75 74 6f 52 75 6e 2e 69 6e 66 } //01 00  %sAutoRun.inf
		$a_00_1 = {61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 } //0a 00  autorun.inf
		$a_03_2 = {83 f8 02 0f 85 90 01 02 00 00 68 90 01 04 53 e8 90 01 04 83 c4 08 85 c0 0f 85 90 01 02 00 00 68 90 01 04 53 e8 90 01 04 83 c4 08 85 c0 0f 85 90 00 } //0a 00 
		$a_03_3 = {83 f8 02 0f 85 90 01 02 00 00 8b 3d 90 01 04 68 90 01 04 56 ff d7 83 c4 08 85 c0 0f 85 90 01 02 00 00 68 90 01 04 56 ff d7 83 c4 08 85 c0 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}