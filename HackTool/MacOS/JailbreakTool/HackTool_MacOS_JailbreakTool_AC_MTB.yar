
rule HackTool_MacOS_JailbreakTool_AC_MTB{
	meta:
		description = "HackTool:MacOS/JailbreakTool.AC!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {69 50 77 6e 64 65 72 33 32 } //01 00 
		$a_00_1 = {68 65 61 70 20 73 70 72 61 79 } //01 00 
		$a_00_2 = {6c 69 6d 65 72 61 31 6e 20 65 78 70 6c 6f 69 74 20 28 68 65 61 70 20 6f 76 65 72 66 6c 6f 77 29 } //02 00 
		$a_00_3 = {48 89 e5 48 83 ec 40 b8 21 00 00 00 b9 01 00 00 00 45 31 c0 41 b9 64 00 00 00 48 89 7d f8 48 89 75 f0 48 89 55 e8 48 8b 7d f8 48 8b 55 f0 48 8b 75 e8 66 41 89 f2 89 c6 48 89 55 e0 89 ca 44 89 c1 4c 8b 5d e0 44 89 4d dc 4d 89 d9 41 0f b7 c2 89 04 24 c7 44 24 08 64 00 00 00 } //01 00 
		$a_00_4 = {46 69 72 6d 77 61 72 65 2f 64 66 75 2f 69 42 53 53 2e 6e 34 32 61 70 2e 52 45 4c 45 41 53 45 2e 64 66 75 } //00 00 
	condition:
		any of ($a_*)
 
}