
rule VirTool_WinNT_Mader_gen_A{
	meta:
		description = "VirTool:WinNT/Mader.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 08 00 00 05 00 "
		
	strings :
		$a_03_0 = {33 c9 33 d2 8d 44 4d 90 01 01 8a 10 81 e2 ff 00 ff ff 83 ea 90 01 01 41 83 f9 90 01 01 66 89 10 7c e6 66 83 65 90 01 01 00 8d 45 90 01 01 50 8d 45 f8 90 00 } //05 00 
		$a_03_1 = {74 44 80 7d 90 01 01 3e 75 2f 80 7d 90 01 01 74 75 29 80 7d 90 01 01 6e 75 23 80 7d 90 01 01 63 75 1d 80 7d 90 01 01 61 75 17 80 7d 90 01 01 63 75 11 80 7d 90 01 01 68 75 0b 80 7d 90 01 01 65 75 05 33 c0 40 eb 02 90 00 } //02 00 
		$a_01_2 = {63 00 6f 00 72 00 65 00 2e 00 63 00 61 00 63 00 68 00 65 00 2e 00 64 00 73 00 6b 00 00 00 } //02 00 
		$a_01_3 = {3e 56 6d 49 6d 67 44 65 73 63 72 69 70 74 6f 72 } //01 00  >VmImgDescriptor
		$a_01_4 = {5c 5c 2e 5c 49 54 4e 44 72 69 76 65 72 } //01 00  \\.\ITNDriver
		$a_01_5 = {3e 46 49 58 4f } //01 00  >FIXO
		$a_01_6 = {3e 49 4e 54 } //01 00  >INT
		$a_01_7 = {3e 58 49 54 } //00 00  >XIT
	condition:
		any of ($a_*)
 
}