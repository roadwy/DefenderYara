
rule VirTool_Win32_Obfuscator_AHJ{
	meta:
		description = "VirTool:Win32/Obfuscator.AHJ,SIGNATURE_TYPE_PEHSTR_EXT,64 00 06 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {45 78 70 6f 72 74 65 64 4d 61 69 6e 46 75 6e 63 74 69 6f 6e } //01 00  ExportedMainFunction
		$a_00_1 = {46 6c 75 65 74 65 72 6d 41 6d 79 6c 52 65 65 66 6f 6e 75 73 4d 75 6d 70 73 63 61 64 } //01 00  FluetermAmylReefonusMumpscad
		$a_00_2 = {47 6f 62 79 63 72 6f 77 73 6d 75 67 4f 76 61 6c 42 61 68 74 4d 6f 6d 73 } //01 00  GobycrowsmugOvalBahtMoms
		$a_00_3 = {4a 6f 6b 65 53 70 65 77 6c 65 61 73 6f 61 74 6d 6d } //02 00  JokeSpewleasoatmm
		$a_02_4 = {55 8b ec 83 e4 f8 81 ec 8c 00 00 00 c7 44 24 18 d6 d5 f6 ff c7 44 24 50 d1 d5 f6 ff c7 44 24 4c 87 20 00 00 a1 90 01 03 00 8b 4c 24 4c 25 02 20 00 00 0d 21 4b 00 00 33 d2 f7 f1 53 56 57 89 54 24 20 66 99 6a 00 ff 15 90 01 03 00 c6 44 24 30 cb 8a 44 24 30 0f b6 c8 b8 8b 00 00 00 99 f7 f9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}