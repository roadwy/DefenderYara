
rule Worm_Win32_Autorun_FL{
	meta:
		description = "Worm:Win32/Autorun.FL,SIGNATURE_TYPE_PEHSTR_EXT,09 00 08 00 07 00 00 03 00 "
		
	strings :
		$a_03_0 = {8a 5d f8 80 fb 41 74 90 01 01 80 fb 42 74 90 01 01 8d 45 f3 50 e8 90 01 04 83 f8 02 75 90 00 } //05 00 
		$a_03_1 = {75 21 6a 02 68 70 f1 00 00 68 12 01 00 00 a1 90 01 04 8b 00 8b 40 90 01 01 50 e8 90 01 04 e9 90 01 03 00 8b 45 fc ba 90 01 04 e8 90 01 04 75 21 6a ff 68 70 f1 00 00 68 12 01 00 00 90 00 } //01 00 
		$a_01_2 = {5b 61 75 74 6f 72 75 6e 5d 00 } //01 00  慛瑵牯湵]
		$a_01_3 = {61 75 74 6f 72 75 6e 2e 69 6e 66 00 } //01 00 
		$a_01_4 = {73 65 72 69 61 6c 3d } //01 00  serial=
		$a_01_5 = {76 65 72 73 69 6f 6e 3d } //01 00  version=
		$a_01_6 = {3a 2a 3a 45 6e 61 62 6c 65 64 3a } //00 00  :*:Enabled:
	condition:
		any of ($a_*)
 
}