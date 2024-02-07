
rule Trojan_BAT_Parpwuts_C{
	meta:
		description = "Trojan:BAT/Parpwuts.C,SIGNATURE_TYPE_PEHSTR_EXT,68 01 54 01 08 00 00 ffffffc8 00 "
		
	strings :
		$a_01_0 = {44 65 64 65 2e 48 6f 6b 6f 2e 72 65 73 6f 75 72 63 65 73 } //64 00  Dede.Hoko.resources
		$a_01_1 = {00 69 55 47 6f 43 54 75 6e 71 6c 59 52 44 63 59 77 6a 5a 6b 6b 56 6c 59 00 } //14 00 
		$a_01_2 = {67 00 50 00 48 00 73 00 5a 00 51 00 4b 00 56 00 48 00 70 00 45 00 4e 00 43 00 67 00 42 00 52 00 4d 00 4b 00 6e 00 51 00 41 00 55 00 57 00 } //14 00  gPHsZQKVHpENCgBRMKnQAUW
		$a_01_3 = {72 00 75 00 76 00 63 00 72 00 71 00 48 00 6a 00 77 00 6d 00 51 00 67 00 59 00 63 00 6e 00 4b 00 6c 00 42 00 49 00 4e 00 63 00 62 00 54 00 } //14 00  ruvcrqHjwmQgYcnKlBINcbT
		$a_01_4 = {6a 00 68 00 69 00 71 00 6a 00 46 00 77 00 49 00 71 00 59 00 4b 00 56 00 67 00 77 00 62 00 6a 00 76 00 50 00 59 00 69 00 48 00 42 00 70 00 } //14 00  jhiqjFwIqYKVgwbjvPYiHBp
		$a_01_5 = {4d 4f 58 61 4c 54 52 67 71 43 49 77 76 72 55 49 62 66 4d } //14 00  MOXaLTRgqCIwvrUIbfM
		$a_01_6 = {50 62 61 64 66 4e 6b 41 50 4d 6c 50 6e 4e 70 77 57 6a 53 43 42 50 65 4f 6d } //14 00  PbadfNkAPMlPnNpwWjSCBPeOm
		$a_01_7 = {4d 59 77 62 6d 4f 4f 42 57 43 72 6a 41 54 51 6b 42 77 55 6b 57 47 6a } //00 00  MYwbmOOBWCrjATQkBwUkWGj
		$a_00_8 = {80 10 00 00 a8 67 f4 3d e7 9f 4b 3d 5d f9 b7 5a 47 01 00 80 80 10 00 00 8d 2e 2c c4 40 67 99 4a d0 37 f0 02 47 01 00 80 80 10 00 00 8d 2e 2c c4 56 e2 10 7a cd 1c f5 04 42 01 00 80 } //5d 04 
	condition:
		any of ($a_*)
 
}