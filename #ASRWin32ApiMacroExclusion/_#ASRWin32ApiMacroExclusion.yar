
rule _#ASRWin32ApiMacroExclusion{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {50 61 6c 69 73 61 64 65 } //01 00 
		$a_00_1 = {44 54 4f 4f 4c 53 38 5f 78 38 36 2e 58 4c 4c } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_2{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_00_0 = {53 4f 50 20 52 65 74 75 72 6e 2e 78 6c 73 6d } //02 00 
		$a_00_1 = {53 4f 50 20 44 61 74 61 20 42 41 43 4b 55 50 2e 78 6c 73 6d } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_3{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_00_0 = {61 70 70 6c 69 63 61 74 69 6f 6e 2e 72 75 6e 28 22 70 69 70 75 74 76 61 6c 22 } //02 00 
		$a_00_1 = {70 69 65 78 74 69 6d 65 76 61 6c } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_4{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 20 28 78 38 36 29 5c 44 50 57 2d 41 70 70 73 5c } //05 00 
		$a_01_1 = {70 61 74 68 6c 69 6e 65 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_5{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 4c 42 32 44 41 54 41 28 29 } //02 00 
		$a_00_1 = {53 75 62 20 54 54 54 53 45 4c 45 43 54 49 4f 4e 28 29 } //02 00 
		$a_00_2 = {53 75 62 20 70 74 64 53 45 4c 45 43 54 49 4f 4e 28 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_6{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {77 77 77 2e 6d 64 66 2d 78 6c 70 61 67 65 73 2e 63 6f 6d } //01 00 
		$a_00_1 = {77 77 77 2e 65 78 63 65 6c 61 62 6f 2e 6e 65 74 } //01 00 
		$a_00_2 = {68 74 74 70 3a 2f 2f 65 78 63 65 6c 2d 6d 61 6c 69 6e 2e 63 6f 6d } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_7{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_00_0 = {41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 57 6f 72 6b 73 68 65 65 74 73 28 22 4e 6f 74 65 73 22 29 2e 41 63 74 69 76 61 74 65 } //02 00 
		$a_00_1 = {43 61 6c 6c 20 4a 72 6e 6c 53 68 65 65 74 5f 53 65 6c 65 63 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_8{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {42 4f 4d 20 55 70 6c 6f 61 64 2e 78 6c 73 78 } //02 00 
		$a_00_1 = {4d 73 67 42 6f 78 20 22 54 68 65 20 42 4f 4d 20 46 69 6c 65 20 68 61 73 20 62 65 65 6e 20 73 61 76 65 64 20 74 6f 20 22 } //01 00 
		$a_00_2 = {53 75 62 20 42 4f 4d 5f 55 70 6c 6f 61 64 28 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_9{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 53 75 62 20 56 65 72 6b 65 74 74 65 6e 5f 47 28 29 } //02 00 
		$a_00_1 = {53 75 62 20 53 41 50 5f 49 6d 70 6f 72 74 47 5f 45 72 7a 65 75 67 65 6e 28 29 } //02 00 
		$a_00_2 = {53 75 62 20 5a 65 69 6c 65 45 69 6e 66 75 67 65 6e 5f 47 28 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_10{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_00_0 = {6e 61 6d 65 3d 22 61 73 61 70 75 74 69 6c 69 74 69 65 73 72 69 62 62 6f 6e 22 } //02 00 
		$a_00_1 = {64 65 73 63 72 69 70 74 69 6f 6e 3d 22 72 69 62 62 6f 6e 20 61 6e 64 20 68 61 6e 64 6c 65 72 20 66 6f 72 20 61 73 61 70 20 75 74 69 6c 69 74 69 65 73 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_11{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,1e 00 1e 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {22 a9 20 22 20 26 20 59 65 61 72 28 4e 6f 77 29 20 26 20 22 2c 20 4d 55 46 47 20 42 61 6e 6b 2e 20 20 41 6c 6c 20 52 69 67 68 74 73 20 52 65 73 65 72 76 65 64 2e } //0a 00 
		$a_01_1 = {43 49 51 54 69 63 6b 65 72 } //0a 00 
		$a_01_2 = {52 41 54 6f 67 67 6c 65 50 46 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_12{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {53 68 65 65 74 73 28 22 50 42 52 5f 54 65 6d 70 6c 61 74 65 22 29 2e 53 65 6c 65 63 74 } //02 00 
		$a_00_1 = {53 75 62 20 65 78 70 6f 5f 63 6c 6f 73 65 50 42 52 28 29 } //02 00 
		$a_00_2 = {50 72 69 76 61 74 65 20 53 75 62 20 53 70 6c 69 74 73 5f 46 4d 54 5f 31 28 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_13{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 42 45 78 31 20 3d 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 28 22 42 45 78 41 6e 61 6c 79 7a 65 72 2e 78 6c 61 21 47 65 74 42 45 78 22 29 } //02 00 
		$a_00_1 = {49 66 20 49 6e 53 74 72 28 6c 4e 61 6d 65 2e 4e 61 6d 65 2c 20 22 42 45 78 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_14{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {73 6f 66 74 77 61 72 65 5c 68 61 76 65 72 5c 64 6c 78 6d 65 6e 75 } //02 00 
		$a_00_1 = {73 6f 66 74 77 61 72 65 5c 68 61 76 65 72 5c 64 6c 78 72 61 6e 67 65 72 } //02 00 
		$a_00_2 = {73 6f 66 74 77 61 72 65 5c 68 61 76 65 72 5c 65 78 63 65 6c 64 61 74 65 66 69 72 73 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_15{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 53 75 62 20 50 6f 70 50 65 74 65 44 65 76 50 77 64 } //02 00 
		$a_00_1 = {50 75 62 6c 69 63 20 53 75 62 20 54 6f 67 67 6c 65 50 72 6f 64 56 65 72 73 69 6f 6e } //02 00 
		$a_00_2 = {50 75 62 6c 69 63 20 53 75 62 20 50 6f 70 50 65 74 65 42 6c 61 63 6b 50 77 64 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_16{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 53 79 73 43 66 67 53 68 74 28 29 } //02 00 
		$a_00_1 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 44 64 43 66 67 53 68 74 28 29 } //02 00 
		$a_00_2 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 44 4d 61 73 74 53 68 74 28 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_17{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {48 53 42 43 6e 65 74 43 68 65 63 6b 2e 56 61 6c 75 65 } //02 00 
		$a_00_1 = {41 63 74 69 76 65 53 68 65 65 74 2e 50 72 6f 74 65 63 74 20 28 22 61 62 65 72 6e 6f 77 61 79 22 29 } //02 00 
		$a_00_2 = {41 63 74 69 76 65 53 68 65 65 74 2e 4e 61 6d 65 20 3d 20 22 57 50 53 53 61 6c 61 72 79 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_18{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {45 72 65 69 67 6e 69 73 73 65 20 64 65 61 6b 74 69 76 69 65 72 65 6e } //02 00 
		$a_00_1 = {42 69 6c 64 73 63 68 69 72 6d 61 6b 74 75 61 6c 69 73 69 65 72 75 6e 67 20 64 65 61 6b 74 69 76 69 65 72 65 6e } //02 00 
		$a_00_2 = {46 65 68 6c 65 72 62 65 68 61 6e 64 6c 75 6e 67 20 65 69 6e 6c 65 69 74 65 6e } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_19{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {63 6e 6e 5f 63 61 73 65 73 2e 43 6c 6f 73 65 3a 20 53 65 74 20 63 6e 6e 5f 63 61 73 65 73 20 3d 20 4e 6f 74 68 69 6e 67 } //02 00 
		$a_00_1 = {46 75 6e 63 74 69 6f 6e 20 46 54 4e 53 41 5f 49 6e 6c 69 6e 65 } //02 00 
		$a_00_2 = {50 72 69 76 61 74 65 20 53 75 62 20 63 6d 62 59 65 61 72 5f 4b 65 79 44 6f 77 6e } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_20{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 41 6e 65 78 61 72 28 29 } //02 00 
		$a_00_1 = {41 74 74 72 69 62 75 74 65 20 41 6e 65 78 61 72 2e 56 42 5f 50 72 6f 63 44 61 74 61 2e 56 42 5f 49 6e 76 6f 6b 65 5f 46 75 6e 63 } //02 00 
		$a_00_2 = {57 69 6e 64 6f 77 73 28 22 53 49 4f 5f 56 61 6c 6c 65 73 2e 78 6c 73 22 29 2e 41 63 74 69 76 61 74 65 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_21{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {50 72 69 76 61 74 65 20 53 75 62 20 63 62 6f 48 6f 6d 65 54 6d 5f 43 68 61 6e 67 65 28 29 } //02 00 
		$a_00_1 = {50 72 69 76 61 74 65 20 53 75 62 20 63 62 78 43 61 72 42 6b 5f 43 68 61 6e 67 65 28 29 } //02 00 
		$a_00_2 = {50 72 69 76 61 74 65 20 53 75 62 20 63 62 6f 4c 6f 61 6e 54 6d 5f 43 68 61 6e 67 65 28 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_22{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {45 69 6e 70 61 72 6b 65 6e 20 4d 61 6b 72 6f } //02 00 
		$a_00_1 = {4d 61 6b 72 6f 20 45 44 56 2d 4e 75 6d 6d 65 72 6e 20 74 61 75 73 63 68 65 6e } //01 00 
		$a_00_2 = {41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 57 6f 72 6b 73 68 65 65 74 73 28 22 45 44 56 2d 52 61 63 6f 73 22 29 2e 41 75 74 6f 46 69 6c 74 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_23{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_00_0 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 53 41 53 48 6f 6d 65 39 34 5c 53 41 53 53 63 72 61 74 63 68 5c 62 69 6e 5c 59 6f 75 72 50 61 67 65 2e 70 64 66 } //02 00 
		$a_00_1 = {43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 53 41 53 48 6f 6d 65 39 34 5c 53 41 53 53 63 72 61 74 63 68 5c 62 69 6e } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_24{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_00_0 = {22 4f 43 47 20 54 72 61 63 6b 65 72 20 56 22 20 26 20 50 61 72 61 6d 73 2e 50 72 6f 70 65 72 74 79 28 22 4f 63 67 54 72 61 63 6b 65 72 56 65 72 73 69 6f 6e 22 29 } //02 00 
		$a_00_1 = {61 6c 6c 20 64 61 74 61 20 68 65 6c 64 20 6f 6e 20 74 68 69 73 20 73 79 73 74 65 6d 20 69 73 20 52 45 53 54 52 49 43 54 45 44 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_25{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {50 72 69 76 61 74 65 20 53 75 62 20 63 62 6f 77 63 44 61 79 5f 43 68 61 6e 67 65 28 29 } //02 00 
		$a_00_1 = {50 72 69 76 61 74 65 20 53 75 62 20 43 68 6b 53 69 6e 67 6c 65 51 75 65 75 65 5f 43 68 61 6e 67 65 28 29 } //02 00 
		$a_00_2 = {50 72 69 76 61 74 65 20 53 75 62 20 6c 62 6c 54 69 74 6c 65 5f 43 6c 69 63 6b 28 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_26{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {40 46 6f 6c 64 65 72 28 22 42 69 6e 6f 63 73 2d 41 50 49 2e 44 65 6d 61 6e 64 22 29 } //02 00 
		$a_00_1 = {44 69 6d 20 62 69 6e 6f 63 73 41 70 69 20 41 73 20 54 61 62 6c 65 41 70 69 4d 61 6e 61 67 65 72 } //02 00 
		$a_00_2 = {53 65 74 20 62 69 6e 6f 63 73 41 70 69 20 3d 20 6e 65 77 54 61 62 6c 65 41 70 69 4d 61 6e 61 67 65 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_27{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 45 6e 74 72 61 64 61 73 53 61 6c 69 64 61 73 28 29 } //02 00 
		$a_00_1 = {50 76 74 4e 6f 6d 62 72 65 20 3d 20 22 70 76 74 45 6e 74 72 61 64 61 73 53 61 6c 69 64 61 73 22 } //02 00 
		$a_00_2 = {57 69 6e 64 6f 77 73 28 22 52 65 70 6f 72 74 65 73 5f 44 69 61 72 69 6f 73 2e 78 6c 73 6d 22 29 2e 41 63 74 69 76 61 74 65 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_28{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {41 63 74 69 76 65 53 68 65 65 74 2e 4e 61 6d 65 20 3d 20 22 42 79 67 67 65 70 6c 61 64 73 22 } //02 00 
		$a_00_1 = {41 63 74 69 76 65 53 68 65 65 74 2e 4e 61 6d 65 20 3d 20 22 48 75 73 6b 65 6c 69 73 74 65 22 } //02 00 
		$a_00_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 68 65 65 74 73 28 22 44 65 74 61 69 6c 6b 61 6c 6b 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_29{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {4e 6f 6d 62 72 65 4d 61 63 72 6f 20 3d 20 22 4e 6f 6d 62 72 65 20 64 65 20 6c 61 20 6d 61 63 72 6f 20 22 } //02 00 
		$a_00_1 = {6d 73 20 3d 20 6d 73 20 26 20 22 53 69 6e 20 6f 70 65 72 61 63 69 6f 6e 20 65 6e 20 63 65 6d 65 78 20 22 } //02 00 
		$a_00_2 = {53 75 62 20 4d 6f 64 75 6c 6f 5f 43 6f 6e 73 75 6c 74 61 72 5f 4f 43 28 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_30{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {27 4d 73 67 42 6f 78 20 22 53 75 63 63 65 73 73 3a 20 50 44 46 20 63 6f 6e 76 65 72 74 65 64 20 69 6e 74 6f 20 54 65 78 74 } //02 00 
		$a_01_1 = {27 41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 74 61 74 75 73 42 61 72 20 3d 20 22 50 44 46 20 4e 61 6d 65 20 63 6f 6e 76 65 72 74 69 6f 6e 20 70 72 6f 63 65 73 73 69 6e 67 2e 2e 2e } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_31{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {46 69 6c 65 4e 61 6d 65 20 3d 20 22 4f 66 66 69 63 69 61 6c 20 53 65 6e 73 69 74 69 76 65 20 51 41 54 52 4f 20 41 73 73 65 73 73 6d 65 6e 74 20 2d 20 22 20 } //02 00 
		$a_00_1 = {53 75 62 20 42 52 50 56 61 6c 69 64 61 74 65 28 29 } //02 00 
		$a_00_2 = {53 75 62 20 4f 72 69 67 69 6e 61 6c 5f 52 65 63 6f 72 64 41 73 79 6c 75 6d 28 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_32{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_00_0 = {42 61 73 74 69 65 6e 20 4d 65 6e 73 69 6e 6b 20 28 61 75 74 68 6f 72 20 6f 66 20 41 53 41 50 20 55 74 69 6c 69 74 69 65 73 20 61 6e 64 20 77 6f 72 6b 69 6e 67 20 6f 6e 20 69 74 20 73 69 6e 63 65 20 31 39 39 39 29 } //02 00 
		$a_00_1 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 61 73 61 70 2d 75 74 69 6c 69 74 69 65 73 2e 63 6f 6d } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_33{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {46 75 6e 63 74 69 6f 6e 20 53 74 61 66 66 69 6e 67 53 74 61 74 73 28 42 79 56 61 6c 20 53 69 74 65 4e 61 6d 65 20 41 73 20 53 74 72 69 6e 67 29 } //02 00 
		$a_00_1 = {63 6e 6e 5f 72 6f 73 74 65 72 2e 45 78 65 63 75 74 65 20 53 51 4c } //02 00 
		$a_00_2 = {46 75 6e 63 74 69 6f 6e 20 57 65 65 6b 6c 79 45 76 65 6e 74 53 74 61 74 73 28 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_34{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {62 6f 64 79 5f 31 20 3d 20 53 68 65 65 74 73 28 22 4d 61 69 6c 22 29 2e 52 61 6e 67 65 28 22 43 37 22 29 } //02 00 
		$a_01_1 = {62 6f 64 79 20 3d 20 53 68 65 65 74 73 28 22 4d 61 69 6c 22 29 2e 52 61 6e 67 65 28 22 43 38 22 29 } //02 00 
		$a_01_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 63 72 65 65 6e 55 70 64 61 74 69 6e 67 20 3d 20 54 72 75 65 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_35{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 70 6c 61 6e 74 75 6d 6c 2e 63 6f 6d 2f 70 61 74 72 65 6f 6e } //02 00 
		$a_00_1 = {42 79 20 43 68 69 70 20 50 65 61 72 73 6f 6e 2c 20 63 68 69 70 40 63 70 65 61 72 73 6f 6e 2e 63 6f 6d 2c 20 77 77 77 2e 63 70 65 61 72 73 6f 6e 2e 63 6f 6d } //02 00 
		$a_00_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 73 6c 69 70 73 74 69 63 6b 2e 63 6f 6d } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_36{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {50 76 74 4e 6f 6d 62 72 65 20 3d 20 22 70 76 74 49 6e 76 65 6e 74 61 72 69 6f 46 69 73 69 63 6f 22 } //02 00 
		$a_00_1 = {4f 62 6a 2e 41 62 72 69 72 20 28 22 43 69 65 72 72 65 44 69 61 72 69 6f 2e 58 4c 53 22 29 } //02 00 
		$a_00_2 = {57 69 6e 64 6f 77 73 28 22 49 4e 56 20 44 49 41 52 49 4f 53 20 4a 43 4e 2e 78 6c 73 6d 22 29 2e 41 63 74 69 76 61 74 65 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_37{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 63 6c 69 65 6e 74 20 3d 20 6e 65 77 57 65 62 43 6c 69 65 6e 74 28 22 68 74 74 70 73 3a 2f 2f 22 20 26 20 62 69 6e 6f 63 73 45 6e 76 69 72 6f 6e 6d 65 6e 74 20 26 20 22 2e 6d 79 62 69 6e 6f 63 73 2e 63 6f 6d 2f 22 29 } //01 00 
		$a_00_1 = {40 46 6f 6c 64 65 72 28 22 42 69 6e 6f 63 73 2d 41 50 49 2e 43 6f 6e 6e 65 63 74 69 6f 6e 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_38{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 43 61 6c 63 75 6c 61 74 65 46 75 6c 6c 52 65 62 75 69 6c 64 } //02 00 
		$a_00_1 = {53 75 62 20 42 75 74 74 6f 6e 52 61 69 6e 66 61 6c 6c 5f 43 6c 69 63 6b 28 29 } //02 00 
		$a_00_2 = {41 74 74 72 69 62 75 74 65 20 70 75 74 5f 64 61 74 61 31 2e 56 42 5f 50 72 6f 63 44 61 74 61 2e 56 42 5f 49 6e 76 6f 6b 65 5f 46 75 6e 63 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_39{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {50 72 69 76 61 74 65 20 43 6f 6e 73 74 20 42 46 46 4d 5f 53 45 54 53 45 4c 45 43 54 49 4f 4e 20 3d 20 57 4d 5f 55 53 45 52 20 2b 20 31 30 32 } //02 00 
		$a_00_1 = {50 72 69 76 61 74 65 20 43 6f 6e 73 74 20 42 46 46 4d 5f 49 4e 49 54 49 41 4c 49 5a 45 44 20 3d 20 31 } //02 00 
		$a_00_2 = {73 74 72 43 6c 61 73 73 4e 61 6d 65 20 3d 20 22 58 4c 4d 41 49 4e 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_40{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {63 61 70 74 75 72 65 5f 69 6e 76 6f 69 63 65 6e 6f 20 3d 20 31 20 54 68 65 6e 20 41 63 74 69 76 65 53 68 65 65 74 2e 43 65 6c 6c 73 28 6c 61 73 74 72 6f 77 2c 20 33 29 } //02 00 
		$a_01_1 = {49 66 20 69 6e 76 6f 69 63 65 64 61 74 65 20 3d 20 31 20 54 68 65 6e 20 41 63 74 69 76 65 53 68 65 65 74 2e 43 65 6c 6c 73 28 6c 61 73 74 72 6f 77 2c 20 34 29 20 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_41{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_00_0 = {4e 61 6d 65 20 3d 20 57 6f 72 6b 73 68 65 65 74 73 28 22 42 6c 61 73 6d 61 73 63 68 69 6e 65 22 29 2e 52 61 6e 67 65 28 22 41 33 22 29 2e 56 61 6c 75 65 20 26 20 22 44 42 30 22 } //02 00 
		$a_00_1 = {4e 61 6d 65 20 3d 20 57 6f 72 6b 73 68 65 65 74 73 28 22 45 74 69 6d 61 22 29 2e 52 61 6e 67 65 28 22 41 33 22 29 2e 56 61 6c 75 65 20 26 20 22 44 42 30 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_42{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 43 6c 65 61 72 5f 43 6f 6e 73 6f 6c 69 64 61 74 65 64 5f 62 79 5f 43 6f 6d 6d 6f 64 69 74 79 28 29 } //02 00 
		$a_00_1 = {53 75 62 20 43 6c 65 61 72 5f 46 6c 6f 75 72 5f 43 6f 6e 74 72 61 63 74 73 5f 62 79 5f 43 4f 50 43 28 29 } //02 00 
		$a_00_2 = {53 75 62 20 43 6c 65 61 72 5f 46 6c 6f 75 72 5f 43 6f 6e 74 72 61 63 74 73 5f 62 79 5f 43 4f 4d 4d 28 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_43{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {50 72 69 76 61 74 65 20 70 41 63 63 4d 6f 64 65 20 41 73 20 53 74 72 69 6e 67 } //02 00 
		$a_00_1 = {70 41 63 63 4d 6f 64 65 20 3d 20 52 65 67 69 73 74 72 79 47 65 74 28 22 47 65 6e 65 72 61 6c 22 2c 20 22 41 63 63 4d 6f 64 65 22 29 } //02 00 
		$a_00_2 = {4d 73 67 42 6f 78 20 22 4e 6f 74 20 70 6f 73 73 69 62 6c 65 20 77 69 74 68 20 53 68 65 65 74 20 44 72 69 6c 6c 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_44{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {61 74 74 72 69 62 75 74 65 20 76 62 5f 6e 61 6d 65 20 3d 20 22 6d 6f 64 63 6f 6e 76 65 72 73 69 6f 6e 22 } //02 00 
		$a_00_1 = {70 75 62 6c 69 63 20 63 6f 6e 73 74 20 61 70 70 6e 61 6d 65 20 61 73 20 73 74 72 69 6e 67 20 3d 20 22 65 75 72 6f 20 61 64 64 2d 69 6e 22 } //02 00 
		$a_00_2 = {70 72 69 76 61 74 65 20 73 75 62 20 65 75 72 6f 5f 63 6f 6e 76 65 72 74 5f 65 78 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_45{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 4e 6f 6e 46 69 6e 61 6e 63 69 61 6c 49 6e 66 6f 54 72 61 6e 73 66 65 72 28 29 } //02 00 
		$a_00_1 = {53 75 62 20 4f 74 68 65 72 45 78 70 65 6e 64 69 74 75 72 65 54 72 61 6e 73 66 65 72 28 29 } //02 00 
		$a_00_2 = {44 65 73 6b 74 6f 70 5c 49 6e 76 6f 69 63 69 6e 67 5c 46 6f 73 74 65 72 69 6e 67 20 50 44 46 20 49 6e 76 6f 69 63 65 73 5c 41 62 65 72 64 65 65 6e } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_46{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {50 72 69 76 61 74 65 20 53 75 62 20 57 61 6b 75 4b 65 69 73 65 6e } //02 00 
		$a_00_1 = {50 75 62 6c 69 63 20 4f 72 61 44 61 74 61 42 61 73 65 20 41 73 20 41 44 4f 44 42 2e 43 6f 6e 6e 65 63 74 69 6f 6e } //02 00 
		$a_00_2 = {50 72 69 76 61 74 65 20 53 75 62 20 4b 65 69 73 65 6e } //02 00 
		$a_00_3 = {50 72 69 76 61 74 65 20 53 75 62 20 43 62 62 4b 73 79 5f 43 68 61 6e 67 65 28 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_47{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 63 6c 73 43 42 52 4d 53 68 65 65 74 73 22 } //02 00 
		$a_00_1 = {47 6c 6f 62 61 6c 20 6d 63 6f 6c 43 42 52 4d 53 68 65 65 74 73 20 41 73 20 63 6f 6c 43 42 52 4d 53 68 65 65 74 73 } //02 00 
		$a_00_2 = {53 65 74 20 6f 62 6a 43 42 52 4d 53 68 65 65 74 73 20 3d 20 4e 65 77 20 63 6c 73 43 42 52 4d 53 68 65 65 74 73 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_48{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {46 75 6e 63 74 69 6f 6e 20 50 72 6f 64 75 63 65 43 61 74 54 65 61 6d 73 28 63 61 74 20 41 73 20 53 74 72 69 6e 67 29 } //02 00 
		$a_00_1 = {50 72 69 76 61 74 65 20 53 75 62 20 63 62 78 5f 4d 61 6e 61 67 65 6d 65 6e 74 5f 43 6c 69 63 6b 28 29 } //02 00 
		$a_00_2 = {46 75 6e 63 74 69 6f 6e 20 53 68 69 66 74 52 65 71 75 65 73 74 73 5f 49 6e 69 74 69 61 6c 53 65 74 75 70 28 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_49{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 53 75 62 20 73 79 6e 63 53 65 6c 65 63 74 69 6f 6e 28 42 79 56 61 6c 20 54 61 72 67 65 74 20 41 73 20 50 69 76 6f 74 54 61 62 6c 65 29 } //02 00 
		$a_00_1 = {49 66 20 49 6e 53 74 72 28 70 66 4d 61 69 6e 2e 4e 61 6d 65 2c 20 22 52 65 67 69 6f 6e 22 29 } //02 00 
		$a_00_2 = {49 6e 53 74 72 28 70 66 4d 61 69 6e 2e 4e 61 6d 65 2c 20 22 42 72 61 6e 64 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_50{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 7a 6f 74 65 72 6f 2e 6f 72 67 } //01 00 
		$a_00_1 = {53 75 62 20 5a 6f 74 65 72 6f 43 6f 6d 6d 61 6e 64 28 63 6d 64 20 41 73 20 53 74 72 69 6e 67 2c 20 62 72 69 6e 67 54 6f 46 72 6f 6e 74 20 41 73 20 42 6f 6f 6c 65 61 6e 29 } //01 00 
		$a_00_2 = {50 75 62 6c 69 63 20 53 75 62 20 5a 6f 74 65 72 6f 49 6e 73 65 72 74 42 69 62 6c 69 6f 67 72 61 70 68 79 28 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_51{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {2e 50 69 76 6f 74 54 61 62 6c 65 73 28 22 70 74 47 72 61 70 68 44 61 74 61 22 29 2e 52 65 66 72 65 73 68 54 61 62 6c 65 } //02 00 
		$a_00_1 = {57 69 74 68 20 2e 50 69 76 6f 74 54 61 62 6c 65 73 28 22 70 74 41 75 64 69 74 54 72 61 69 6c 22 29 } //02 00 
		$a_00_2 = {41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 55 6e 70 72 6f 74 65 63 74 20 22 4e 6f 72 74 68 67 61 74 65 70 73 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_52{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 45 6e 75 6d 20 46 72 6d 44 62 6c 50 72 6f 67 72 65 73 73 4c 65 76 65 6c } //02 00 
		$a_00_1 = {75 74 69 6c 46 69 6c 65 73 2e 4c 6f 61 64 53 6f 75 72 63 65 46 69 6c 65 20 46 70 61 74 68 2c 20 52 61 77 53 68 74 4e 6d 2c 20 22 5f 72 65 73 22 } //02 00 
		$a_00_2 = {57 61 73 50 72 6f 74 20 3d 20 44 4d 61 73 74 53 68 74 2e 50 72 6f 74 65 63 74 43 6f 6e 74 65 6e 74 73 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_53{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,1e 00 1e 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {42 5f 56 41 54 5f 57 48 54 5f 44 74 6c 73 } //0a 00 
		$a_01_1 = {56 61 74 57 69 74 68 68 6f 6c 64 69 6e 67 45 78 63 65 6c 44 54 4f 2e 74 6f 74 61 6c 50 61 79 61 62 6c 65 41 6d 6f 75 6e 74 } //0a 00 
		$a_01_2 = {50 49 4e 4e 6f 20 3d 20 57 6f 72 6b 73 68 65 65 74 73 28 22 41 5f 42 61 73 69 63 5f 49 6e 66 6f 22 29 2e 52 61 6e 67 65 28 22 53 65 63 41 2e 50 49 4e 22 29 2e 76 61 6c 75 65 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_54{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 61 73 61 70 2d 75 74 69 6c 69 74 69 65 73 2e 63 6f 6d } //02 00 
		$a_00_1 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 41 53 41 50 6c 49 6c 49 49 6c 6c 6c 6c 6c 6c 6c 49 6c 49 6c 6c 49 6c 49 49 49 49 6c 49 22 } //01 00 
		$a_00_2 = {50 72 69 76 61 74 65 20 53 75 62 20 55 73 65 72 46 6f 72 6d 5f 49 6e 69 74 69 61 6c 69 7a 65 28 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_55{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 50 51 4d 5f 52 65 70 6f 72 74 22 } //02 00 
		$a_00_1 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 50 51 4d 5f 41 75 74 6f 6d 61 74 69 6f 6e 22 } //02 00 
		$a_00_2 = {53 65 74 20 70 50 51 4d 43 6f 6e 6e 65 63 74 69 6f 6e 20 3d 20 67 5f 6f 62 6a 41 70 70 2e 41 63 74 69 76 65 43 6f 6e 6e 65 63 74 69 6f 6e } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_56{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {76 62 43 72 69 74 69 63 61 6c 2c 20 22 49 54 47 20 44 65 73 69 67 6e 20 7c 20 41 64 64 44 65 73 69 67 6e 50 67 22 } //02 00 
		$a_00_1 = {53 65 74 20 76 69 73 4d 73 74 72 20 3d 20 76 69 73 4d 73 74 72 73 2e 49 74 65 6d 28 22 43 4b 54 44 65 6d 61 72 6b 22 29 } //02 00 
		$a_00_2 = {76 62 43 72 69 74 69 63 61 6c 2c 20 22 49 54 47 20 44 65 73 69 67 6e 20 7c 20 41 64 64 58 50 52 54 50 67 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_57{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 42 31 20 3d 20 53 68 65 65 74 73 28 61 72 6b 65 74 29 2e 42 75 74 74 6f 6e 73 28 22 4f 70 72 65 74 50 65 6e 73 69 6f 6e 4b 6f 6e 74 6f 4b 6e 61 70 22 29 } //02 00 
		$a_00_1 = {53 75 62 20 4f 70 72 65 74 50 65 6e 73 69 6f 6e 4b 6f 6e 74 69 4b 6e 61 70 28 29 } //02 00 
		$a_00_2 = {50 72 69 76 61 74 65 20 53 75 62 20 6f 70 72 65 74 5f 70 65 6e 73 69 6f 6e 6b 6f 6e 74 69 28 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_58{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {43 68 65 6d 44 72 61 77 45 78 63 65 6c 41 64 64 49 6e 32 31 2e 45 78 63 65 6c 41 64 64 49 6e } //01 00 
		$a_00_1 = {63 64 78 6c 64 6f 63 75 6d 65 6e 74 } //01 00 
		$a_00_2 = {43 53 58 4c 5f 53 68 6f 77 53 74 72 75 63 74 75 72 65 44 72 61 77 69 6e 67 73 } //01 00 
		$a_00_3 = {43 44 58 4c 41 64 64 49 6e 50 72 6f 67 49 44 } //01 00 
		$a_00_4 = {43 53 58 4c 5f 4d 61 6b 65 4e 65 77 43 53 57 6f 72 6b 73 68 65 65 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_59{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {6f 53 6f 75 72 63 65 42 6f 6f 6b 2e 53 61 76 65 41 73 20 73 54 61 72 67 65 74 50 66 61 64 20 26 20 22 54 72 61 66 6f 64 61 74 65 6e 5f 62 65 72 65 69 6e 69 67 74 2e 78 6c 73 78 22 } //02 00 
		$a_00_1 = {55 73 65 72 66 6f 72 6d 20 65 69 6e 62 6c 65 6e 64 65 6e 20 28 6e 69 63 68 74 20 6d 6f 64 61 6c 29 } //02 00 
		$a_00_2 = {53 75 62 20 44 61 74 65 6e 5f 62 65 72 65 69 6e 69 67 65 6e 28 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_60{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,0f 00 0f 00 04 00 00 0a 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 61 73 61 70 2d 75 74 69 6c 69 74 69 65 73 2e 63 6f 6d } //05 00 
		$a_00_1 = {42 61 73 74 69 65 6e 20 4d 65 6e 73 69 6e 6b } //05 00 
		$a_00_2 = {41 74 74 72 69 62 75 74 65 20 42 75 74 74 6f 6e 47 72 6f 75 70 44 79 6e 61 6d 69 63 2e 56 42 5f 56 61 72 48 65 6c 70 49 44 } //05 00 
		$a_00_3 = {50 72 69 76 61 74 65 20 54 79 70 65 20 53 48 46 49 4c 45 4f 50 53 54 52 55 43 54 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_61{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {50 72 69 76 61 74 65 20 43 6f 6e 73 74 20 4d 6f 64 75 6c 65 4e 61 6d 65 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 41 64 64 69 6e 52 65 70 6f 72 74 55 49 22 } //02 00 
		$a_00_1 = {53 68 65 65 74 73 28 22 41 64 64 2d 69 6e 20 44 65 74 61 69 6c 73 22 29 2e 41 63 74 69 76 61 74 65 } //02 00 
		$a_00_2 = {53 75 62 20 41 64 6f 70 74 65 64 53 75 70 70 6f 72 74 65 64 47 72 6f 75 70 5f 43 6c 69 63 6b 28 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_62{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {53 65 72 76 65 72 4e 61 6d 65 20 3d 20 22 48 4b 53 51 4c 2d 49 4b 41 5c 48 4b 53 51 4c 49 4b 41 22 } //02 00 
		$a_00_1 = {64 6e 61 6d 65 20 3d 20 22 49 6b 61 73 61 6e 30 31 22 } //02 00 
		$a_00_2 = {75 4e 61 6d 65 20 3d 20 22 53 59 53 5f 49 4b 41 50 52 44 5f 53 51 4c 22 } //02 00 
		$a_00_3 = {64 65 66 5f 73 75 62 6a 65 63 74 20 3d 20 22 46 69 64 65 73 73 61 20 4f 72 64 65 72 20 52 65 70 6f 72 74 20 2d 20 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_63{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {61 74 74 72 69 62 75 74 65 20 76 62 5f 6e 61 6d 65 20 3d 20 22 63 68 72 6f 6e 69 63 6c 65 73 65 78 70 6f 72 74 22 } //02 00 
		$a_00_1 = {70 72 69 76 61 74 65 20 63 6f 6e 73 74 20 6d 6f 64 75 6c 65 20 3d 20 22 65 70 69 63 20 65 78 70 6f 72 74 20 6d 61 63 72 6f 22 } //02 00 
		$a_00_2 = {6f 6e 61 63 74 69 6f 6e 20 3d 20 22 63 68 72 6f 6e 69 63 6c 65 73 65 78 70 6f 72 74 2e 65 78 70 6f 72 74 64 61 74 61 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_64{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 57 6f 72 6b 73 68 65 65 74 73 28 22 43 6f 6e 74 72 6f 6c 22 29 2e 41 63 74 69 76 61 74 65 } //02 00 
		$a_00_1 = {41 74 74 72 69 62 75 74 65 20 47 65 74 4d 73 67 2e 56 42 5f 50 72 6f 63 44 61 74 61 2e 56 42 5f 49 6e 76 6f 6b 65 5f 46 75 6e 63 20 3d 20 22 20 5c 6e 31 34 22 } //02 00 
		$a_00_2 = {47 65 74 4d 73 67 20 3d 20 22 4a 72 6e 6c 4c 6f 67 2e 78 6c 73 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_65{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {63 72 65 61 74 65 46 58 43 6f 76 65 72 61 67 65 45 6d 61 69 6c 2e 56 42 5f 50 72 6f 63 44 61 74 61 2e 56 42 5f 49 6e 76 6f 6b 65 5f 46 75 6e 63 } //02 00 
		$a_00_1 = {63 72 65 61 74 65 46 58 43 6f 76 65 72 61 67 65 45 6d 61 69 6c 43 6f 6d 70 6c 69 61 6e 63 65 } //02 00 
		$a_00_2 = {50 6c 65 61 73 65 20 66 69 6e 64 20 61 74 74 61 63 68 65 64 20 74 68 65 20 46 58 20 43 6f 76 65 72 61 67 65 20 52 65 70 6f 72 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_66{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 46 61 7a 53 70 69 65 67 65 6c 28 29 } //02 00 
		$a_00_1 = {53 75 62 20 46 61 7a 53 70 69 65 67 65 6c 44 69 72 28 73 44 69 72 29 } //02 00 
		$a_00_2 = {63 6f 6e 66 69 67 5c 46 61 7a 73 70 69 65 67 65 6c 2e 69 6e 69 } //02 00 
		$a_00_3 = {4d 73 67 42 6f 78 20 22 42 69 74 74 65 20 6e 75 74 7a 65 6e 20 73 69 65 20 64 69 65 20 4d 75 73 74 65 72 76 6f 72 6c 61 67 65 20 46 61 7a 73 70 69 65 67 65 6c 2e 78 6c 74 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_67{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 44 65 76 65 6c 6f 70 65 72 20 3d 20 22 6d 65 6c 76 69 6c 63 22 } //02 00 
		$a_00_1 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 53 68 6f 72 74 63 75 74 5f 4e 61 6d 65 20 3d 20 22 44 41 43 20 50 6f 72 74 61 6c 2e 6c 6e 6b 22 } //02 00 
		$a_00_2 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 50 6f 72 74 61 6c 5f 46 69 6c 65 4e 61 6d 65 20 3d 20 22 50 6f 72 74 61 6c 2e 78 6c 73 6d 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_68{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_00_0 = {43 72 65 64 69 74 73 3a 20 68 74 74 70 3a 2f 2f 77 77 77 2e 64 72 65 61 6d 69 6e 63 6f 64 65 2e 6e 65 74 2f 63 6f 64 65 2f 73 6e 69 70 70 65 74 35 34 30 2e 68 74 6d } //02 00 
		$a_00_1 = {47 42 52 20 4e 4f 54 45 3a 20 54 68 69 73 20 77 6f 72 6b 73 2c 20 62 75 74 20 77 65 20 68 61 76 65 20 6e 6f 20 61 63 63 65 73 73 20 74 6f 20 73 74 64 69 6e 2c 20 73 74 64 6f 75 74 20 6f 72 20 73 74 64 65 72 72 2e 2e 2e } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_69{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 52 65 66 72 65 73 68 5f 41 43 54 5f 46 43 53 54 5f 4c 4d 52 28 29 } //02 00 
		$a_00_1 = {61 63 63 41 70 70 2e 64 6f 63 6d 64 2e 6f 70 65 6e 71 75 65 72 79 20 28 22 4c 4d 52 20 52 65 63 68 6e 75 6e 67 73 64 61 74 65 6e 20 55 70 64 61 74 65 20 54 61 62 65 6c 6c 65 22 29 } //02 00 
		$a_00_2 = {75 4f 46 4e 2e 73 44 6c 67 54 69 74 6c 65 20 3d 20 22 44 61 74 65 69 20 73 70 65 69 63 68 65 72 6e 20 75 6e 74 65 72 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_70{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {50 72 69 76 61 74 65 20 43 6f 6e 73 74 20 6d 5f 50 41 53 53 57 4f 52 44 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 50 75 6c 73 30 30 33 31 31 34 22 } //02 00 
		$a_00_1 = {52 69 62 62 6f 6e 43 6f 6e 74 72 6f 6c 52 65 66 72 65 73 68 20 22 62 74 6e 52 65 73 65 74 4d 61 72 6b 73 22 } //02 00 
		$a_00_2 = {53 65 74 20 6d 5f 6f 52 6f 6f 74 20 3d 20 47 65 74 4f 62 6a 65 63 74 28 22 4c 44 41 50 3a 2f 2f 52 6f 6f 74 44 53 45 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_71{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 41 70 70 4e 61 6d 65 20 3d 20 22 47 54 20 50 44 46 4d 65 6c 64 20 54 6f 6f 6c 6b 69 74 22 } //01 00 
		$a_00_1 = {43 6f 6e 73 74 20 50 44 46 42 61 74 63 68 46 69 6c 65 20 3d 20 22 52 75 6e 50 44 46 4d 65 6c 64 2e 62 61 74 22 } //01 00 
		$a_00_2 = {41 75 74 68 6f 72 20 3a 20 45 6a 61 7a 20 41 68 6d 65 64 20 2d 20 65 6a 61 7a 2e 61 68 6d 65 64 2e 31 39 38 39 40 67 6d 61 69 6c 2e 63 6f 6d } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_72{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 62 6f 6f 6b 20 3d 20 77 62 2e 57 6f 72 6b 62 6f 6f 6b 73 2e 41 64 64 28 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 50 61 74 68 20 26 20 22 5c 73 70 69 6e 6e 65 72 2e 78 6c 73 6d 22 29 } //01 00 
		$a_00_1 = {53 75 62 20 44 6f 43 61 6c 63 54 69 6d 65 72 28 6a 4d 65 74 68 6f 64 20 41 73 20 4c 6f 6e 67 29 } //01 00 
		$a_00_2 = {46 75 6e 63 74 69 6f 6e 20 4d 69 63 72 6f 54 69 6d 65 72 28 29 20 41 73 20 44 6f 75 62 6c 65 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_73{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {42 61 74 46 69 6c 65 20 3d 20 22 63 3a 5c 74 65 6d 70 5c 73 6f 66 74 6c 69 6e 6b 70 72 6f 6d 6f 74 65 74 6f 6d 61 73 74 65 72 2e 63 6d 64 22 } //02 00 
		$a_00_1 = {42 61 74 46 69 6c 65 20 3d 20 22 63 3a 5c 74 65 6d 70 5c 73 6f 66 74 6c 69 6e 6b 62 72 61 6e 63 68 73 65 74 75 70 2e 63 6d 64 22 } //02 00 
		$a_00_2 = {6d 66 69 6c 65 2c 20 22 70 6c 69 6e 6b 20 2d 70 77 20 62 75 69 6c 64 20 62 75 69 6c 64 40 74 68 65 74 61 20 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_74{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 66 64 20 3d 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 46 69 6c 65 44 69 61 6c 6f 67 28 6d 73 6f 46 69 6c 65 44 69 61 6c 6f 67 46 6f 6c 64 65 72 50 69 63 6b 65 72 29 } //01 00 
		$a_00_1 = {41 75 74 68 6f 72 3a 20 44 61 76 69 64 20 4d 6f 73 69 65 72 2c 20 4e 65 69 6c 20 4a 6f 68 6e 73 6f 6e } //01 00 
		$a_00_2 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 44 41 47 73 46 69 6c 65 20 3d 20 22 44 41 47 49 6e 66 6f 2e 63 73 76 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_75{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 53 75 62 46 6f 6c 64 65 72 32 20 3d 20 53 75 62 46 6f 6c 64 65 72 2e 46 6f 6c 64 65 72 73 28 22 4e 49 4e 4f 20 76 32 20 49 50 54 20 54 69 65 72 20 32 20 65 6d 61 69 6c 73 22 29 } //02 00 
		$a_00_1 = {50 75 62 6c 69 63 20 53 75 62 20 4d 6f 76 65 45 6d 61 69 6c 73 54 6f 49 50 54 41 72 63 68 69 76 65 28 29 } //02 00 
		$a_00_2 = {44 69 6d 20 49 6e 62 6f 78 20 41 73 20 4f 75 74 6c 6f 6f 6b 2e 4d 41 50 49 46 6f 6c 64 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_76{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {46 75 6e 63 74 69 6f 6e 20 72 65 63 75 70 65 72 65 5f 74 61 62 6c 65 5f 75 74 69 6c 69 73 61 74 65 75 72 73 28 29 20 41 73 20 56 61 72 69 61 6e 74 } //02 00 
		$a_00_1 = {53 71 6c 20 3d 20 22 53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 30 35 5f 55 50 53 5f 43 72 65 77 20 22 } //02 00 
		$a_00_2 = {53 75 62 20 52 65 74 72 6f 75 76 65 5f 61 6e 61 6c 79 73 65 73 5f 6e 6f 6e 5f 72 65 6c 65 61 73 65 65 73 5f 73 61 6e 73 5f 65 6d 61 69 6c 28 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_77{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 74 68 69 73 57 6f 72 6b 73 68 65 65 74 20 3d 20 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 57 6f 72 6b 73 68 65 65 74 73 28 22 43 50 20 43 6c 69 65 6e 74 22 29 } //02 00 
		$a_00_1 = {53 75 62 20 74 72 61 6e 73 66 65 72 5f 62 69 6e 61 72 69 65 73 5f 74 6f 5f 4d 65 74 61 4d 6f 6e 28 29 } //02 00 
		$a_00_2 = {53 75 62 20 74 72 61 6e 73 66 65 72 5f 62 69 6e 61 72 69 65 73 5f 74 6f 5f 4c 33 5f 74 65 73 74 5f 74 65 61 6d 28 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_78{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 6c 5f 63 6f 6e 74 72 6f 6c 20 3d 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 43 6f 6d 6d 61 6e 64 42 61 72 73 2e 46 69 6e 64 43 6f 6e 74 72 6f 6c 28 54 61 67 3a 3d 22 44 46 57 46 69 6c 74 65 72 22 29 } //01 00 
		$a_00_1 = {53 65 74 20 6c 53 68 61 70 65 20 3d 20 6c 53 68 65 65 74 2e 53 68 61 70 65 73 28 22 49 6e 66 6f 41 22 29 } //01 00 
		$a_00_2 = {49 6e 53 74 72 28 31 2c 20 6c 53 68 61 70 65 2e 4e 61 6d 65 2c 20 22 42 45 78 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_79{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {45 50 4c 41 4e 34 5c 45 58 43 45 4c 5c 58 4c 53 31 33 38 42 2e 58 4c 53 20 32 30 30 34 2d 30 32 2d 30 35 } //02 00 
		$a_00_1 = {50 75 62 6c 69 63 20 41 6e 7a 65 69 67 65 5f 50 72 6f 7a 65 6e 74 20 41 73 20 53 74 72 69 6e 67 } //02 00 
		$a_00_2 = {50 75 62 6c 69 63 20 41 72 74 69 6b 65 6c 6b 65 6e 6e 75 6e 67 20 41 73 20 4c 6f 6e 67 } //02 00 
		$a_00_3 = {50 75 62 6c 69 63 20 4d 65 72 6b 65 72 5f 41 72 74 69 6b 65 6c 74 79 70 20 41 73 20 4c 6f 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_80{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 53 68 6f 72 74 63 75 74 5f 4e 61 6d 65 20 3d 20 22 53 53 52 43 20 50 6f 72 74 61 6c 2e 6c 6e 6b 22 } //02 00 
		$a_00_1 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 49 63 6f 6e 5f 44 65 73 63 72 69 70 74 69 6f 6e 20 3d 20 22 53 53 52 43 20 50 6f 72 74 61 6c 22 } //02 00 
		$a_00_2 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 50 6f 72 74 61 6c 5f 46 69 6c 65 4e 61 6d 65 20 3d 20 22 50 6f 72 74 61 6c 2e 78 6c 73 6d 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_81{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 57 6f 72 6b 73 68 65 65 74 73 28 22 36 20 2d 20 49 6e 66 61 6e 74 20 46 65 65 64 69 6e 67 22 29 } //02 00 
		$a_00_1 = {53 65 72 76 69 63 65 43 6f 6d 62 6f 42 6f 78 31 2e 41 64 64 49 74 65 6d 20 22 54 6f 6e 67 75 65 2d 74 69 65 20 73 75 70 70 6f 72 74 22 } //02 00 
		$a_00_2 = {41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 57 6f 72 6b 73 68 65 65 74 73 28 22 4f 75 74 70 75 74 73 5f 53 46 4c 49 46 4d 48 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_82{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {44 65 63 6c 61 72 65 20 50 74 72 53 61 66 65 20 46 75 6e 63 74 69 6f 6e 20 58 4c 50 79 44 4c 4c 4e 44 69 6d 73 20 4c 69 62 20 22 78 6c 77 69 6e 67 73 36 34 2e 64 6c 6c 22 } //02 00 
		$a_00_1 = {50 72 69 76 61 74 65 20 44 65 63 6c 61 72 65 20 50 74 72 53 61 66 65 20 46 75 6e 63 74 69 6f 6e 20 58 4c 50 79 44 4c 4c 4e 44 69 6d 73 20 4c 69 62 20 22 78 6c 77 69 6e 67 73 33 32 2e 64 6c 6c 22 } //02 00 
		$a_00_2 = {78 6c 77 69 6e 67 73 5f 6c 6f 67 2e 74 78 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_83{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 65 69 6e 67 61 62 65 62 6c 61 74 74 46 6f 72 6d 65 6c 6e 28 29 } //01 00 
		$a_00_1 = {53 65 74 20 77 73 20 3d 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 57 6f 72 6b 73 68 65 65 74 73 28 22 45 69 6e 67 61 62 65 22 29 } //01 00 
		$a_00_2 = {73 61 66 65 70 61 74 68 20 3d 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 50 61 74 68 20 26 20 22 5c 4d 46 54 2d 4e 2d 50 61 74 65 6e 2d 42 6c 61 74 74 2e 78 6c 73 78 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_84{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {50 72 69 76 61 74 65 20 46 75 6e 63 74 69 6f 6e 20 47 65 6e 55 75 69 64 28 73 55 75 69 64 20 41 73 20 53 74 72 69 6e 67 29 20 41 73 20 42 6f 6f 6c 65 61 6e } //01 00 
		$a_00_1 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 69 73 53 41 50 44 6f 63 28 6b 65 79 20 41 73 20 53 74 72 69 6e 67 29 20 41 73 20 42 6f 6f 6c 65 61 6e } //01 00 
		$a_00_2 = {43 61 73 65 20 49 73 20 3d 20 22 53 41 50 47 72 6f 75 70 22 20 20 27 20 53 74 79 6c 65 73 20 67 72 6f 75 70 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_85{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {50 6c 65 61 73 65 20 73 65 6c 65 63 74 20 61 20 63 65 6c 6c 20 74 68 61 74 20 69 73 20 6e 6f 74 20 62 6c 61 6e 6b 20 6f 72 20 63 6f 6e 74 61 69 6e 73 20 61 20 76 61 6c 69 64 61 74 69 6f 6e 20 6c 69 73 74 } //02 00 
		$a_01_1 = {4c 69 73 74 73 20 74 68 61 74 20 63 6f 6e 74 61 69 6e 20 6d 6f 72 65 20 74 68 61 6e 20 32 2c 30 30 30 20 69 74 65 6d 73 20 6d 61 79 20 74 61 6b 65 20 61 64 64 69 74 69 6f 6e 61 6c 20 74 69 6d 65 20 74 6f 20 73 6f 72 74 2e } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_86{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 44 6f 43 61 6c 63 54 69 6d 65 72 28 6a 4d 65 74 68 6f 64 20 41 73 20 4c 6f 6e 67 29 } //02 00 
		$a_00_1 = {53 65 74 20 62 6f 6f 6b 20 3d 20 77 62 2e 57 6f 72 6b 62 6f 6f 6b 73 2e 41 64 64 28 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 50 61 74 68 20 26 20 22 5c 73 70 69 6e 6e 65 72 2e 78 6c 73 6d 22 29 } //02 00 
		$a_00_2 = {73 43 61 6c 63 54 79 70 65 20 3d 20 22 52 65 63 61 6c 63 75 6c 61 74 65 20 6f 70 65 6e 20 77 6f 72 6b 62 6f 6f 6b 73 3a 20 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_87{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {57 6f 72 6b 62 6f 6f 6b 73 28 22 41 53 41 50 20 55 74 69 6c 69 74 69 65 73 2e 78 6c 61 6d 22 29 2e 50 61 74 68 } //02 00 
		$a_00_1 = {41 53 41 50 52 69 62 62 6f 6e 5f 49 6e 69 74 69 61 6c 69 7a 65 28 72 69 62 62 6f 6e 20 41 73 20 49 52 69 62 62 6f 6e 55 49 29 } //02 00 
		$a_00_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 22 41 53 41 50 52 75 6e 50 72 6f 63 5f 78 36 34 22 } //02 00 
		$a_00_3 = {77 77 77 2e 61 73 61 70 2d 75 74 69 6c 69 74 69 65 73 2e 63 6f 6d } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_88{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {63 6c 73 50 72 6f 70 65 72 74 69 65 73 2e 72 65 6d 6f 76 65 50 72 6f 70 65 72 74 79 20 22 49 43 58 5f 53 45 53 53 49 4f 4e 5f 49 44 22 } //02 00 
		$a_00_1 = {45 52 56 4c 45 54 5f 50 41 54 48 20 3d 20 22 68 74 74 70 3a 2f 2f 65 62 73 70 72 64 2e 68 6f 6d 65 6f 66 66 69 63 65 2e 61 6d 63 2e 63 6f 72 70 3a 38 30 2f 4f 41 5f 48 54 4d 4c 2f 22 } //02 00 
		$a_00_2 = {50 75 62 6c 69 63 20 53 75 62 20 42 6e 65 4f 6e 43 72 65 61 74 65 50 72 6f 63 65 64 75 72 65 28 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_89{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {50 72 69 76 61 74 65 20 43 6f 6e 73 74 20 50 41 54 48 44 45 53 54 20 3d 20 22 48 3a 5c 63 61 70 61 63 69 74 79 5c 54 6f 6f 6c 5c 44 61 74 61 } //02 00 
		$a_00_1 = {50 72 69 76 61 74 65 20 43 6f 6e 73 74 20 50 41 54 48 44 45 53 54 44 41 54 41 53 20 3d 20 22 48 3a 5c 63 61 70 61 63 69 74 79 5c 54 6f 6f 6c 5c 50 6f 63 5f 44 61 74 61 73 } //02 00 
		$a_00_2 = {73 74 72 53 71 6c 20 3d 20 22 55 70 64 61 74 65 43 61 70 61 70 6c 61 6e 6e 69 6e 67 56 4d 53 69 7a 65 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_90{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {43 61 6c 6c 20 70 6f 70 75 6c 61 74 65 5f 47 6c 6f 62 61 6c 73 } //02 00 
		$a_00_1 = {49 66 20 74 4d 69 6c 65 73 74 6f 6e 65 73 28 74 61 73 6b 43 6f 75 6e 74 29 2e 70 72 6f 6a 55 49 44 20 3d 20 22 52 65 74 61 69 6c 20 52 65 63 6f 72 64 73 20 4d 61 6e 61 67 65 6d 65 6e 74 20 50 72 6f 67 72 61 6d 6d 65 2d 31 38 34 22 20 54 68 65 6e 20 53 74 6f 70 } //02 00 
		$a_00_2 = {53 75 62 20 6c 69 6e 6b 5f 4d 69 6c 65 73 74 6f 6e 65 73 28 70 72 65 49 44 2c 20 73 75 63 49 44 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_91{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 50 4f 5f 43 61 6e 63 65 6c 6c 61 74 69 6f 6e 5f 50 72 6f 63 65 73 73 28 29 } //02 00 
		$a_00_1 = {53 68 65 65 74 73 28 22 50 4f 20 44 65 74 61 69 6c 73 22 29 } //02 00 
		$a_00_2 = {50 4f 5f 41 64 73 20 3d 20 53 41 50 53 63 72 69 70 74 2e 46 69 6e 64 5f 41 64 64 73 28 22 53 61 6c 65 73 20 6f 72 64 65 72 20 6e 6f 22 29 3a 20 4d 61 74 5f 41 64 73 20 3d 20 53 41 50 53 63 72 69 70 74 2e 46 69 6e 64 5f 41 64 64 73 28 22 50 61 72 74 20 4e 75 6d 62 65 72 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_92{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 74 61 74 75 73 42 61 72 20 3d 20 22 50 72 65 70 61 72 69 6e 67 20 66 6f 72 20 53 41 4d 50 20 61 6e 61 6c 79 73 69 73 22 } //02 00 
		$a_00_1 = {49 66 20 55 43 61 73 65 28 56 42 43 6f 6e 73 74 61 6e 74 73 2e 52 61 6e 67 65 28 22 53 41 4d 50 5f 52 55 4e 5f 44 41 54 45 22 29 2e 56 61 6c 75 65 32 29 20 3c 3e 20 22 22 20 54 68 65 6e 20 45 78 69 74 20 53 75 62 } //02 00 
		$a_00_2 = {43 61 6c 6c 20 46 69 78 5f 52 69 62 62 6f 6e 5f 4d 50 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_93{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 47 65 6e 65 72 61 74 65 53 46 52 51 75 65 72 79 28 29 } //01 00 
		$a_00_1 = {4d 73 67 42 6f 78 20 22 53 46 52 20 71 75 65 72 79 20 63 6f 70 69 65 64 20 74 6f 20 63 6c 69 70 62 6f 61 72 64 22 } //01 00 
		$a_00_2 = {73 66 72 5f 6c 69 6e 6b 20 3d 20 22 68 74 74 70 3a 2f 2f 73 66 72 2f 70 72 6f 64 41 73 70 2f 73 63 72 69 70 74 73 2f 4d 53 47 2f 73 66 72 2e 61 73 70 3f 73 66 72 3d 22 } //01 00 
		$a_00_3 = {53 75 62 20 43 72 65 61 74 65 53 46 52 44 65 73 63 4c 69 73 74 28 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_94{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {54 68 65 20 53 68 61 72 65 64 20 43 6f 6e 74 72 6f 6c 20 52 6f 6f 6d 20 53 4f 43 43 55 49 20 69 73 20 61 6c 72 65 61 64 79 20 6f 70 65 6e } //02 00 
		$a_01_1 = {54 68 69 73 20 77 69 6c 6c 20 72 65 73 75 6c 74 20 69 6e 20 63 68 61 6e 67 65 73 20 73 61 76 65 64 20 69 6e 20 74 68 65 20 53 4f 43 43 55 49 } //02 00 
		$a_01_2 = {43 6c 6f 73 69 6e 67 20 74 68 69 73 20 63 6f 70 79 20 6f 66 20 74 68 65 20 53 68 61 72 65 64 20 43 6f 6e 74 72 6f 6c 20 52 6f 6f 6d 20 53 4f 43 43 55 49 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_95{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 61 64 64 5f 4d 69 6c 65 73 74 6f 6e 65 73 28 73 68 6f 77 53 6c 69 70 2c 20 78 6c 4e 61 6d 65 29 } //01 00 
		$a_00_1 = {43 6f 6d 6d 65 6e 63 69 6e 67 20 52 65 70 6f 72 74 69 6e 67 } //01 00 
		$a_00_2 = {52 65 74 61 69 6c 20 52 65 63 6f 72 64 73 20 4d 61 6e 61 67 65 6d 65 6e 74 20 50 72 6f 67 72 61 6d 6d 65 2d 31 38 34 } //01 00 
		$a_00_3 = {74 4d 69 6c 65 73 74 6f 6e 65 73 28 74 61 73 6b 43 6f 75 6e 74 29 } //01 00 
		$a_00_4 = {22 4d 69 6c 65 73 74 6f 6e 65 20 53 77 69 6d 6c 61 6e 65 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_96{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,1e 00 1e 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {49 6d 70 72 65 73 73 69 6f 6e 20 64 75 20 66 6f 72 6d 75 6c 61 69 72 65 20 64 27 61 75 64 69 74 20 35 53 20 70 6f 75 72 20 6c 65 73 20 73 74 6f 63 6b 73 } //0a 00 
		$a_01_1 = {6c 65 74 74 72 65 73 20 70 6f 75 72 20 61 66 66 69 63 68 61 67 65 20 73 75 72 20 6c 65 20 74 61 62 6c 65 61 75 20 64 65 20 73 65 63 74 65 75 72 } //0a 00 
		$a_01_2 = {27 20 43 68 6f 69 78 20 61 6c e9 61 74 6f 69 72 65 20 64 65 20 6c 61 20 71 75 65 73 74 69 6f 6e 20 65 6e 76 69 72 6f 6e 6e 65 6d 65 6e 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_97{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 44 69 65 73 65 41 72 62 65 69 74 73 6d 61 70 70 65 22 } //02 00 
		$a_00_1 = {53 65 74 20 6f 42 61 72 20 3d 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 43 6f 6d 6d 61 6e 64 42 61 72 73 2e 41 64 64 28 22 4b 52 4f 4e 45 53 22 29 } //02 00 
		$a_00_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 43 6f 6d 6d 61 6e 64 42 61 72 73 28 22 4b 52 4f 4e 45 53 22 29 2e 43 6f 6e 74 72 6f 6c 73 28 22 45 78 65 63 75 74 65 22 29 2e 44 65 6c 65 74 65 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_98{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {50 6c 65 61 73 65 20 75 70 67 72 61 64 65 20 54 68 6f 6d 73 6f 6e 20 52 65 75 74 65 72 73 20 45 69 6b 6f 6e 20 45 78 63 65 6c } //01 00 
		$a_00_1 = {50 6c 65 61 73 65 20 73 69 67 6e 20 69 6e 20 74 6f 20 54 68 6f 6d 73 6f 6e 20 52 65 75 74 65 72 73 20 45 69 6b 6f 6e 20 45 78 63 65 6c } //01 00 
		$a_00_2 = {43 6f 6d 6d 61 6e 64 54 65 78 74 20 3d 20 41 72 72 61 79 28 22 53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 5b 68 74 74 70 3a 2f 2f 66 6c 6f 77 20 67 61 73 73 63 6f 20 6e 6f 2f 5d 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_99{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {50 72 69 76 61 74 65 20 43 6f 6e 73 74 20 66 72 61 6d 65 43 61 70 74 69 6f 6e 24 20 3d 20 22 49 6d 70 61 63 74 20 6f 6e 20 4e 61 74 69 6f 6e 61 6c 20 53 65 63 75 72 69 74 79 20 2f 20 49 6e 66 72 61 73 74 72 75 63 74 75 72 65 22 } //02 00 
		$a_00_1 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 46 69 78 55 70 5f 63 72 69 6d 69 6e 61 6c 69 74 79 44 61 74 61 28 29 } //02 00 
		$a_00_2 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 46 69 78 55 70 5f 6d 61 6e 61 67 65 6d 65 6e 74 44 61 74 61 28 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_100{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 52 45 6e 64 20 3d 20 53 68 65 65 74 73 28 22 4e 47 4c 20 53 44 46 49 20 2d 20 49 4b 4b 45 20 52 } //01 00 
		$a_00_1 = {52 22 29 2e 52 61 6e 67 65 28 22 41 34 30 30 22 29 2e 45 6e 64 28 78 6c 55 70 29 2e 4f 66 66 73 65 74 28 30 2c 20 33 29 } //01 00 
		$a_00_2 = {53 65 74 20 52 53 74 61 72 74 20 3d 20 52 61 6e 67 65 28 22 41 32 22 29 } //01 00 
		$a_00_3 = {49 66 20 57 6f 72 6b 73 68 65 65 74 46 75 6e 63 74 69 6f 6e 2e 43 6f 75 6e 74 42 6c 61 6e 6b 28 2e 52 6f 77 73 28 69 29 29 20 3d 20 34 20 54 68 65 6e } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_101{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {57 6f 72 64 49 6e 74 65 67 72 61 74 69 6f 6e 2e 46 69 6c 6c 4c 69 73 74 57 6f 72 64 74 61 62 6c 65 20 63 62 50 72 6f 64 75 63 74 73 2c 20 22 65 3a 5c 57 6f 72 64 54 65 6d 70 6c 61 74 65 5c 44 61 74 61 5c 50 72 6f 64 75 63 74 73 2e 64 6f 63 6d 22 } //01 00 
		$a_00_1 = {63 62 50 72 6f 64 75 63 74 73 2c 20 22 68 74 74 70 3a 2f 2f 63 6f 6d 70 61 73 73 32 73 69 74 65 73 2e 70 65 72 73 63 6f 72 70 2e 63 6f 6d 2f 73 69 74 65 73 2f 31 31 36 33 2f 44 61 74 61 2f 50 72 6f 64 75 63 74 73 2e 64 6f 63 6d 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_102{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 54 69 74 75 6c 6f 20 3d 20 22 53 65 6c 65 63 69 6f 6e 65 20 75 6d 20 61 72 71 75 69 76 6f 20 44 4f 43 22 } //01 00 
		$a_00_1 = {4d 6f 64 65 6c 6f 20 70 61 72 61 20 55 6e 69 72 20 6f 73 20 54 52 56 73 2e 64 6f 63 6d } //01 00 
		$a_00_2 = {53 65 74 20 44 4f 43 20 3d 20 57 6f 72 64 2e 44 6f 63 75 6d 65 6e 74 73 2e 4f 70 65 6e 28 6c 50 61 73 74 61 20 26 20 22 5c 55 6e 69 54 52 56 73 2e 64 6f 63 6d 22 29 } //01 00 
		$a_00_3 = {50 75 62 6c 69 63 20 53 75 62 20 64 69 72 65 74 6f 72 69 6f 5f 6d 6f 64 65 6c 6f 5f 44 4f 43 28 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_103{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,0a 00 0a 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {50 72 69 76 61 74 65 20 53 75 62 20 54 42 44 69 73 63 72 65 74 69 6f 6e 5f 43 68 61 6e 67 65 28 29 } //02 00 
		$a_00_1 = {50 72 69 76 61 74 65 20 53 75 62 20 54 42 52 65 61 64 79 74 6f 43 61 73 65 77 6f 72 6b 5f 43 68 61 6e 67 65 28 29 } //02 00 
		$a_00_2 = {50 72 69 76 61 74 65 20 53 75 62 20 50 72 65 42 69 6f 43 6f 70 79 32 28 29 } //02 00 
		$a_00_3 = {50 72 69 76 61 74 65 20 53 75 62 20 53 68 61 72 65 50 65 72 66 6f 72 6d 61 6e 63 65 31 28 29 } //02 00 
		$a_00_4 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 71 75 61 63 6b 69 74 2e 63 6f 6d } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_104{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {41 74 74 72 69 62 75 74 65 20 63 72 65 61 74 65 4e 61 6d 65 64 52 61 6e 67 65 73 2e 56 42 5f 50 72 6f 63 44 61 74 61 2e 56 42 5f 49 6e 76 6f 6b 65 5f 46 75 6e 63 20 3d 20 } //01 00 
		$a_00_1 = {63 6f 6c 4e 6f 20 3d 20 72 61 6e 67 65 28 22 7a 44 6c 67 50 65 72 69 6f 64 73 22 29 2e 43 6f 6c 75 6d 6e 73 28 72 61 6e 67 65 28 22 7a 44 6c 67 50 65 72 69 6f 64 73 22 29 2e 43 6f 6c 75 6d 6e 73 2e 43 6f 75 6e 74 29 2e 43 6f 6c 75 6d 6e 20 2b 20 31 } //01 00 
		$a_00_2 = {66 69 6c 65 6e 61 6d 65 20 3d 20 45 6e 76 69 72 6f 6e 24 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_105{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {44 74 6f 6f 6c 73 5f 47 65 74 45 78 63 65 70 74 69 6f 6e 49 6e 66 6f 56 42 } //01 00 
		$a_00_1 = {4d 6f 73 74 20 6f 66 20 74 68 65 20 63 61 6c 6c 73 20 68 65 72 65 20 61 72 65 20 73 69 6d 70 6c 79 20 77 72 61 70 70 65 72 73 20 66 6f 72 20 63 61 6c 6c 69 6e 67 20 69 6e 74 6f 20 44 74 6f 6f 6c 73 2e 78 6c 6c } //01 00 
		$a_00_2 = {44 74 6f 6f 6c 73 5f 52 69 73 6b 46 69 6e 64 49 6e 70 75 74 73 41 6e 64 4f 75 74 70 75 74 73 } //01 00 
		$a_00_3 = {57 72 61 70 70 65 72 73 20 66 6f 72 20 44 74 6f 6f 6c 73 20 46 75 6e 63 74 69 6f 6e 73 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_106{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {43 6f 6e 73 74 20 58 4c 50 79 44 4c 4c 4e 61 6d 65 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 78 6c 77 69 6e 67 73 36 34 2d 30 2e 31 35 2e 31 30 2e 64 6c 6c 22 } //02 00 
		$a_00_1 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 58 4c 57 49 4e 47 53 5f 56 45 52 53 49 4f 4e 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 30 2e 31 35 2e 31 30 22 } //02 00 
		$a_00_2 = {50 79 2e 53 65 74 41 74 74 72 20 50 79 2e 4d 6f 64 75 6c 65 28 22 78 6c 77 69 6e 67 73 2e 5f 78 6c 77 69 6e 64 6f 77 73 22 29 2c 20 22 42 4f 4f 4b 5f 43 41 4c 4c 45 52 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_107{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 73 3a 2f 2f 73 61 70 70 72 64 31 35 6d 73 2e 72 65 64 6d 6f 6e 64 2e 63 6f 72 70 2e 6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d 2f 73 61 70 2f 62 63 2f 75 69 32 2f 66 6c 70 23 53 68 65 6c 6c 2d 68 6f 6d 65 } //01 00 
		$a_00_1 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 73 66 63 2e 68 6b 2f 65 6e 2f 52 65 67 75 6c 61 74 6f 72 79 2d 66 75 6e 63 74 69 6f 6e 73 2f 50 72 6f 64 75 63 74 73 2f 4c 69 73 74 2d 6f 66 2d 45 53 47 2d 66 75 6e 64 73 } //01 00 
		$a_00_2 = {50 75 62 6c 69 63 20 53 75 62 20 53 65 6c 65 6e 69 75 6d 28 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_108{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {50 61 74 68 4e 61 6d 65 4f 75 74 20 3d 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 50 61 74 68 20 26 20 22 5c 30 31 5f 46 41 55 46 2d 46 65 68 6c 65 72 5c 22 } //02 00 
		$a_00_1 = {6f 70 66 6e 20 3d 20 22 46 41 55 46 5f 46 65 68 6c 65 72 5f 22 20 26 20 52 69 67 68 74 24 28 54 4d 50 2c 20 32 29 } //02 00 
		$a_00_2 = {2e 53 75 62 6a 65 63 74 20 3d 20 22 42 44 45 20 46 65 68 6c 65 72 6d 6f 6e 69 74 6f 72 22 } //02 00 
		$a_00_3 = {43 4c 4d 53 28 31 29 20 3d 20 22 46 65 68 6c 65 72 64 61 74 75 6d 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_109{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {44 69 6d 20 77 73 5f 5a 75 6f 72 64 6e 75 6e 67 20 41 73 20 57 6f 72 6b 73 68 65 65 74 } //01 00 
		$a_00_1 = {53 65 74 20 77 73 5f 5a 75 6f 72 64 6e 75 6e 67 20 3d 20 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 57 6f 72 6b 73 68 65 65 74 73 28 22 5a 75 6f 72 64 6e 75 6e 67 22 29 } //01 00 
		$a_00_2 = {77 73 5f 5a 75 6f 72 64 6e 75 6e 67 2e 52 61 6e 67 65 28 22 42 31 22 29 20 3d 20 44 61 74 65 } //01 00 
		$a_00_3 = {53 65 74 20 72 65 73 20 3d 20 77 73 5f 5a 75 6f 72 64 6e 75 6e 67 2e 52 61 6e 67 65 28 22 41 31 3a 41 31 30 30 30 30 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_110{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {4d 73 67 42 6f 78 20 45 72 72 2e 4e 75 6d 62 65 72 20 26 20 22 20 22 20 26 20 45 72 72 2e 44 65 73 63 72 69 70 74 69 6f 6e 2c 20 76 62 43 72 69 74 69 63 61 6c 2c 20 22 49 54 47 20 44 65 73 69 67 6e 20 7c 20 41 64 64 44 65 73 69 67 6e 50 67 22 } //02 00 
		$a_00_1 = {53 65 74 20 76 69 73 4d 73 74 72 20 3d 20 76 69 73 4d 73 74 72 73 2e 49 74 65 6d 28 22 54 72 61 6e 73 70 53 69 74 65 22 29 } //02 00 
		$a_00_2 = {53 65 74 20 76 69 73 4d 73 74 72 20 3d 20 76 69 73 4d 73 74 72 73 2e 49 74 65 6d 28 22 43 4b 54 44 65 6d 61 72 6b 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_111{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {41 75 74 68 6f 72 20 2d 20 50 72 61 73 68 61 6e 74 20 44 65 73 68 70 61 6e 64 65 } //01 00 
		$a_00_1 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 4e 61 6d 65 73 2e 61 64 64 20 6e 61 6d 65 3a 3d 22 50 6f 70 43 61 63 68 65 5f 47 4c 5f 49 4e 54 45 52 46 41 43 45 5f 52 45 46 45 52 45 4e 43 45 37 22 } //01 00 
		$a_00_2 = {43 4c 41 53 53 3a 42 6e 65 56 42 41 50 61 72 61 6d 65 74 65 72 } //01 00 
		$a_00_3 = {50 72 69 76 61 74 65 20 43 6f 6e 73 74 20 4c 4f 47 5f 53 48 45 45 54 20 3d 20 22 42 6e 65 4c 6f 67 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_112{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 53 75 62 20 5a 6f 74 65 72 6f 49 6e 73 65 72 74 42 69 62 6c 69 6f 67 72 61 70 68 79 28 29 } //01 00 
		$a_00_1 = {53 75 62 20 5a 6f 74 65 72 6f 43 6f 6d 6d 61 6e 64 28 63 6d 64 20 41 73 20 53 74 72 69 6e 67 2c 20 62 72 69 6e 67 54 6f 46 72 6f 6e 74 20 41 73 20 42 6f 6f 6c 65 61 6e 29 } //01 00 
		$a_00_2 = {61 70 70 4e 61 6d 65 73 28 31 29 20 3d 20 22 5a 6f 74 65 72 6f 22 } //01 00 
		$a_00_3 = {43 61 6c 6c 20 5a 6f 74 65 72 6f 43 6f 6d 6d 61 6e 64 28 22 61 64 64 45 64 69 74 43 69 74 61 74 69 6f 6e 22 2c 20 54 72 75 65 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_113{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 03 00 "
		
	strings :
		$a_00_0 = {6e 61 6d 65 3d 22 79 69 65 6c 64 62 6f 6f 6b 61 64 64 69 6e 22 } //03 00 
		$a_00_1 = {64 65 73 63 72 69 70 74 69 6f 6e 3d 22 79 69 65 6c 64 20 62 6f 6f 6b 20 65 78 63 65 6c 20 61 64 64 2d 69 6e 22 } //01 00 
		$a_00_2 = {22 6c 6f 73 73 20 73 63 65 6e 61 72 69 6f 20 64 65 66 69 6e 69 74 69 6f 6e 22 } //01 00 
		$a_00_3 = {22 73 63 65 6e 61 72 69 6f 20 61 6e 61 6c 79 73 69 73 20 66 75 6e 63 74 69 6f 6e 20 62 75 69 6c 64 65 72 22 } //01 00 
		$a_00_4 = {22 70 79 20 66 75 6e 63 74 69 6f 6e 20 62 75 69 6c 64 65 72 22 } //01 00 
		$a_00_5 = {22 65 73 67 20 64 61 74 61 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_114{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 43 72 65 61 74 65 54 65 61 6d 73 4d 43 44 52 65 70 6f 72 74 28 70 70 61 70 70 20 41 73 20 4f 62 6a 65 63 74 2c 20 70 70 70 72 65 73 20 41 73 20 4f 62 6a 65 63 74 29 } //02 00 
		$a_00_1 = {53 65 74 20 6d 6f 72 65 20 3d 20 57 6f 72 6b 73 68 65 65 74 73 28 22 56 6f 69 63 65 20 44 61 74 61 22 29 2e 43 65 6c 6c 73 28 63 6f 75 6e 74 65 72 2c 20 31 29 } //02 00 
		$a_00_2 = {41 63 74 69 76 65 53 68 65 65 74 2e 43 68 61 72 74 4f 62 6a 65 63 74 73 28 22 43 6f 73 74 53 61 76 69 6e 67 73 43 68 61 72 74 22 29 2e 41 63 74 69 76 61 74 65 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_115{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 4c 6f 61 64 4d 61 74 68 54 79 70 65 43 6f 6d 6d 61 6e 64 73 28 29 20 41 73 20 42 6f 6f 6c 65 61 6e } //01 00 
		$a_00_1 = {4f 70 65 6e 73 20 74 68 65 20 4d 61 74 68 54 79 70 65 20 48 65 6c 70 20 66 69 6c 65 20 74 6f 20 61 20 70 61 72 74 69 63 75 6c 61 72 20 74 6f 70 69 63 } //01 00 
		$a_00_2 = {66 6f 6c 64 65 72 20 3d 20 47 65 74 4d 61 74 68 54 79 70 65 44 69 72 20 26 20 22 3a 22 } //01 00 
		$a_00_3 = {6c 6f 67 46 69 6c 65 4e 61 6d 65 20 3d 20 22 4d 54 5f 56 42 41 5f 41 73 73 65 72 74 73 2e 6c 6f 67 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_116{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {47 6c 6f 62 61 6c 20 6d 63 6f 6c 43 42 52 4d 53 68 65 65 74 73 20 41 73 20 63 6f 6c 43 42 52 4d 53 68 65 65 74 73 } //02 00 
		$a_00_1 = {4c 65 6e 28 53 68 65 65 74 73 28 6d 73 74 72 57 6f 72 6b 73 68 65 65 74 29 2e 43 65 6c 6c 73 28 6c 52 6f 77 2c 20 6d 69 6e 74 41 73 73 65 74 49 44 43 6f 6c 29 2e 56 61 6c 75 65 29 } //02 00 
		$a_00_2 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 41 64 64 28 6f 62 6a 43 61 6c 49 74 65 6d 20 41 73 20 63 6c 73 43 61 6c 49 74 65 6d 2c 20 4f 70 74 69 6f 6e 61 6c 20 73 4b 65 79 20 41 73 20 53 74 72 69 6e 67 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_117{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {43 6f 6e 73 74 20 53 45 52 56 4c 45 54 5f 50 41 54 48 20 3d 20 22 68 74 74 70 3a 2f 2f 61 64 65 6c 70 68 69 2e 70 6f 69 73 65 2e 68 6f 6d 65 6f 66 66 69 63 65 2e 6c 6f 63 61 6c 3a 38 30 2f 6f 61 5f 73 65 72 76 6c 65 74 73 2f 22 } //02 00 
		$a_00_1 = {50 72 69 76 61 74 65 20 53 75 62 20 49 56 42 53 41 58 45 72 72 6f 72 48 61 6e 64 6c 65 72 5f 69 67 6e 6f 72 61 62 6c 65 57 61 72 6e 69 6e 67 } //02 00 
		$a_00_2 = {50 72 69 76 61 74 65 20 53 75 62 20 49 56 42 53 41 58 43 6f 6e 74 65 6e 74 48 61 6e 64 6c 65 72 5f 73 74 61 72 74 45 6c 65 6d 65 6e 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_118{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 76 62 43 6f 6d 70 20 3d 20 76 62 50 2e 56 42 43 6f 6d 70 6f 6e 65 6e 74 73 28 22 45 52 44 5f 4d 6f 64 75 6c 65 22 29 } //01 00 
		$a_00_1 = {6d 61 69 6e 46 69 6c 65 50 61 74 68 20 3d 20 6d 61 69 6e 46 69 6c 65 50 61 74 68 20 2b 20 22 5c 45 52 44 5f 4d 6f 64 75 6c 65 22 } //01 00 
		$a_00_2 = {76 62 43 6f 6d 70 2e 4e 61 6d 65 20 3d 20 22 45 52 44 5f 4d 6f 64 75 6c 65 22 } //01 00 
		$a_00_3 = {4f 6e 20 45 72 72 6f 72 20 47 6f 54 6f 20 43 72 65 61 74 65 45 52 44 } //01 00 
		$a_00_4 = {4d 73 67 42 6f 78 20 22 43 72 65 61 74 65 20 45 52 44 20 66 61 69 6c 65 64 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_119{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 66 2e 54 6f 70 20 3d 20 41 63 74 69 76 65 50 72 65 73 65 6e 74 61 74 69 6f 6e 2e 53 6c 69 64 65 4d 61 73 74 65 72 2e 53 68 61 70 65 73 28 22 63 68 46 72 65 65 7a 65 22 29 2e 54 6f 70 } //01 00 
		$a_00_1 = {43 61 6c 6c 20 75 70 64 61 74 65 5f 54 69 6d 65 6c 69 6e 65 28 43 44 61 74 65 28 22 31 2d 4e 6f 76 2d 32 30 31 36 22 29 2c 20 31 2c 20 46 61 6c 73 65 2c 20 39 29 } //01 00 
		$a_00_2 = {41 63 74 69 76 65 50 72 65 73 65 6e 74 61 74 69 6f 6e 2e 53 6c 69 64 65 4d 61 73 74 65 72 2e 53 68 61 70 65 73 28 22 63 68 46 72 65 65 7a 65 22 29 2e 43 6f 70 79 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_120{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {74 61 62 6c 65 73 2e 41 64 64 20 28 22 53 46 52 20 63 75 73 74 6f 6d 65 72 20 6e 6f 74 65 73 22 29 } //01 00 
		$a_00_1 = {45 78 65 63 75 74 65 20 67 65 74 73 66 72 2e 70 79 2c 20 77 68 69 63 68 20 6f 70 65 6e 20 61 20 62 72 6f 77 73 65 72 20 77 69 6e 64 6f 77 20 77 69 74 68 20 74 68 65 20 53 46 52 20 71 75 65 72 79 } //01 00 
		$a_00_2 = {43 68 65 63 6b 20 69 66 20 53 46 52 20 6e 75 6d 62 65 72 73 20 68 61 76 65 20 62 65 65 6e 20 69 6d 70 6f 72 74 65 64 } //01 00 
		$a_00_3 = {53 65 74 20 73 66 72 53 68 65 65 74 20 3d 20 53 68 65 65 74 73 28 22 53 46 52 73 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_121{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {52 61 6e 67 65 28 22 43 31 3a 43 22 20 26 20 6c 61 73 74 72 6f 77 29 2e 46 6f 72 6d 75 6c 61 52 31 43 31 20 3d 20 22 53 74 61 66 66 20 50 61 79 72 6f 6c 6c 20 28 53 47 29 22 } //01 00 
		$a_00_1 = {52 61 6e 67 65 28 22 43 31 3a 43 22 20 26 20 6c 61 73 74 72 6f 77 29 2e 46 6f 72 6d 75 6c 61 52 31 43 31 20 3d 20 22 4d 41 4e 41 47 45 4d 45 4e 54 20 50 41 59 52 4f 4c 4c 20 28 53 47 29 22 } //01 00 
		$a_00_2 = {53 75 62 20 53 74 61 66 66 53 61 6c 45 47 69 72 6f 50 4c 55 53 28 29 } //01 00 
		$a_00_3 = {53 75 62 20 4d 67 6d 74 53 61 6c 45 47 69 72 6f 50 4c 55 53 28 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_122{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 66 6f 72 74 65 73 67 6c 6f 62 61 6c 2e 63 6f 6d } //02 00 
		$a_00_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 66 69 73 7a 2e 6e 6c } //02 00 
		$a_00_2 = {73 74 72 4c 6f 63 61 6c 65 28 53 55 50 50 4f 52 54 4d 41 49 4c 54 4f 29 20 3d 20 22 6d 61 69 6c 74 6f 3a 73 75 70 70 6f 72 74 40 66 6f 72 74 65 73 2e 6e 6c 22 } //02 00 
		$a_00_3 = {73 74 72 4c 6f 63 61 6c 65 28 49 4e 53 45 52 54 4b 45 59 57 4f 52 44 53 55 52 4c 29 20 3d 20 22 69 6e 73 65 72 74 69 6e 67 5f 70 72 69 6e 63 69 70 61 6c 5f 74 6f 6f 6c 62 6f 78 5f 6b 65 2e 68 74 6d 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_123{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {69 6e 76 6f 69 63 65 20 6e 75 6d 62 65 72 20 63 6f 6e 76 65 72 74 20 69 6e 20 55 70 70 61 72 20 43 61 73 65 20 20 65 6e 64 } //02 00 
		$a_01_1 = {43 68 65 63 6b 20 50 49 4e 20 46 6f 72 6d 61 74 20 61 6e 64 20 63 6f 6e 76 65 72 74 20 69 6e 20 55 70 70 61 72 20 43 61 73 65 20 53 74 61 72 74 } //02 00 
		$a_01_2 = {42 61 73 65 20 6f 6e 20 54 61 78 61 62 6c 65 20 76 61 6c 75 65 20 52 65 6c 65 76 61 6e 74 20 49 6e 76 6f 69 63 65 20 44 61 74 65 } //02 00 
		$a_01_3 = {43 68 65 63 6b 20 52 65 6c 65 76 61 6e 74 20 49 6e 76 6f 69 63 65 20 44 61 74 65 20 46 6f 72 6d 61 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_124{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {50 72 69 76 61 74 65 20 54 79 70 65 20 44 74 6f 6f 6c 73 50 72 6f 66 69 6c 65 53 74 61 74 73 } //01 00 
		$a_00_1 = {72 63 20 3d 20 44 74 6f 6f 6c 73 5f 47 65 74 44 74 6f 6f 6c 73 49 6e 73 74 61 6e 63 65 49 64 28 29 } //01 00 
		$a_00_2 = {43 68 65 63 6b 20 69 66 20 44 74 6f 6f 6c 73 20 69 73 20 61 6c 72 65 61 64 79 20 6c 6f 61 64 65 64 20 69 6e 20 74 68 65 20 45 78 63 65 6c 20 61 70 70 6c 69 63 61 74 69 6f 6e } //01 00 
		$a_00_3 = {72 63 20 3d 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 45 76 61 6c 75 61 74 65 28 22 3d 44 74 6f 6f 6c 73 56 65 72 73 69 6f 6e 28 29 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_125{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {53 65 6c 65 63 74 69 6f 6e 2e 41 75 74 6f 46 69 6c 74 65 72 20 66 69 65 6c 64 3a 3d 32 2c 20 43 72 69 74 65 72 69 61 31 3a 3d 63 72 69 74 65 72 69 61 31 5f 76 61 6c 75 65 } //02 00 
		$a_01_1 = {53 65 6c 65 63 74 69 6f 6e 2e 41 75 74 6f 46 69 6c 74 65 72 20 66 69 65 6c 64 3a 3d 33 2c 20 43 72 69 74 65 72 69 61 31 3a 3d 63 72 69 74 65 72 69 61 32 5f 76 61 6c 75 65 } //02 00 
		$a_01_2 = {53 65 6c 65 63 74 69 6f 6e 2e 41 75 74 6f 46 69 6c 74 65 72 20 66 69 65 6c 64 3a 3d 34 2c 20 43 72 69 74 65 72 69 61 31 3a 3d 63 72 69 74 65 72 69 61 33 5f 76 61 6c 75 65 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_126{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 42 45 78 31 20 3d 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 28 22 42 45 78 41 6e 61 6c 79 7a 65 72 2e 78 6c 61 21 47 65 74 42 45 78 22 29 } //01 00 
		$a_00_1 = {53 65 74 20 6c 5f 63 6f 6e 74 72 6f 6c 20 3d 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 43 6f 6d 6d 61 6e 64 42 61 72 73 2e 46 69 6e 64 43 6f 6e 74 72 6f 6c 28 54 61 67 3a 3d 22 44 46 57 46 69 6c 74 65 72 22 29 } //01 00 
		$a_00_2 = {53 68 65 65 74 32 2e 43 65 6c 6c 73 28 31 37 20 2b 20 28 32 20 2a 20 69 29 2c 20 32 39 29 2e 56 61 6c 75 65 20 3d 20 22 5a 43 4d 50 4f 5f 43 4f 4d 50 41 4e 59 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_127{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {50 72 69 76 61 74 65 20 46 75 6e 63 74 69 6f 6e 20 42 6e 65 44 6f 63 75 6d 65 6e 74 5f 6f 6e 63 6c 69 63 6b 28 29 20 41 73 20 42 6f 6f 6c 65 61 6e } //01 00 
		$a_00_1 = {6f 62 6a 50 61 72 61 6d 73 2e 61 64 64 20 22 62 6e 65 3a 70 61 67 65 22 2c 20 22 42 6e 65 44 6f 77 6e 6c 6f 61 64 53 74 61 74 65 22 } //01 00 
		$a_00_2 = {50 72 69 76 61 74 65 20 43 6f 6e 73 74 20 4c 4f 47 5f 53 48 45 45 54 20 3d 20 22 42 6e 65 4c 6f 67 22 } //01 00 
		$a_00_3 = {41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 57 6f 72 6b 73 68 65 65 74 73 28 69 6e 74 43 6e 74 29 2e 42 6e 65 53 74 61 72 74 75 70 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_128{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {50 72 69 76 61 74 65 20 43 6f 6e 73 74 20 44 47 49 5f 53 4f 55 52 43 45 5f 45 53 54 49 4d 41 54 49 4f 4e 5f 53 48 45 45 54 5f 4e 41 4d 45 20 3d 20 22 45 66 66 6f 72 74 20 65 73 74 69 6d 61 74 69 6f 6e 73 22 } //02 00 
		$a_00_1 = {50 72 69 76 61 74 65 20 43 6f 6e 73 74 20 44 47 49 5f 45 53 54 49 4d 41 54 49 4f 4e 5f 53 48 45 45 54 5f 4e 41 4d 45 20 3d 20 22 44 47 49 20 45 66 66 6f 72 74 20 65 73 74 69 6d 61 74 69 6f 6e 73 22 } //02 00 
		$a_00_2 = {50 72 69 76 61 74 65 20 46 75 6e 63 74 69 6f 6e 20 67 65 74 44 67 69 45 73 74 69 6d 61 74 69 6f 6e 57 6f 72 6b 62 6f 6f 6b } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_129{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_00_0 = {41 63 74 69 76 65 43 68 61 72 74 2e 43 68 61 72 74 54 69 74 6c 65 2e 54 65 78 74 20 3d 20 22 50 72 6f 64 75 63 74 69 6f 6e 20 2f 20 43 6f 6e 73 75 6d 70 74 69 6f 6e 22 20 26 20 22 20 75 70 20 74 6f 20 22 20 26 20 76 5a 61 65 68 6c 65 72 20 2a 20 32 34 20 26 20 22 20 68 22 } //02 00 
		$a_00_1 = {41 63 74 69 76 65 43 68 61 72 74 2e 43 68 61 72 74 54 69 74 6c 65 2e 54 65 78 74 20 3d 20 22 50 72 6f 64 75 6b 74 69 6f 6e 20 2f 20 56 65 72 62 72 61 75 63 68 22 20 26 20 22 20 62 69 73 20 7a 75 20 22 20 26 20 76 5a 61 65 68 6c 65 72 20 2a 20 32 34 20 26 20 22 20 68 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_130{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {49 66 20 4e 6f 74 20 69 73 53 41 50 44 6f 63 28 44 6f 63 2e 4e 61 6d 65 29 20 54 68 65 6e } //01 00 
		$a_00_1 = {53 75 62 20 73 61 70 5f 67 65 74 4c 61 62 65 6c 28 63 6f 6e 74 72 6f 6c 20 41 73 20 49 52 69 62 62 6f 6e 43 6f 6e 74 72 6f 6c 2c 20 42 79 52 65 66 20 72 65 74 75 72 6e 65 64 56 61 6c 29 } //01 00 
		$a_00_2 = {43 61 73 65 20 49 73 20 3d 20 22 53 41 50 47 72 6f 75 70 31 22 20 27 20 56 69 65 77 20 67 72 6f 75 70 } //01 00 
		$a_00_3 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 69 73 53 41 50 44 6f 63 28 6b 65 79 20 41 73 20 53 74 72 69 6e 67 29 20 41 73 20 42 6f 6f 6c 65 61 6e } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_131{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {6d 79 66 69 6c 65 20 3d 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 70 61 74 68 20 26 20 22 5c 54 58 54 50 44 46 2e 74 78 74 22 } //01 00 
		$a_00_1 = {44 69 6d 20 64 65 6c 6c 5f 6f 72 64 65 72 5f 6c 69 6e 65 5f 61 72 72 61 79 20 41 73 20 56 61 72 69 61 6e 74 } //01 00 
		$a_00_2 = {64 65 6c 6c 6e 6f 20 3d 20 49 6e 53 74 72 28 55 43 61 73 65 28 74 65 78 74 6c 69 6e 65 29 2c 20 55 43 61 73 65 28 22 44 65 6c 6c 20 4f 72 64 65 72 20 4e 6f 3a 22 29 29 } //01 00 
		$a_00_3 = {4d 73 67 42 6f 78 20 22 53 75 63 63 65 73 73 3a 20 50 44 46 20 63 6f 6e 76 65 72 74 65 64 20 69 6e 74 6f 20 54 65 78 74 2e 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_132{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 6d 61 63 72 6f 5f 73 68 74 20 3d 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 57 6f 72 6b 73 68 65 65 74 73 28 22 45 78 74 72 61 5f 50 64 66 5f 44 61 74 61 22 29 } //02 00 
		$a_00_1 = {6d 61 63 72 6f 5f 73 68 74 2e 43 65 6c 6c 73 28 69 2c 20 31 36 29 20 3d 20 22 59 6c 6d 31 30 20 2d 20 4e 6f 20 50 61 72 74 20 4e 75 6d 62 65 72 22 } //02 00 
		$a_00_2 = {6c 73 74 5f 70 75 72 71 74 79 5f 63 75 6e 74 20 3d 20 55 42 6f 75 6e 64 28 53 70 6c 69 74 28 73 70 6c 69 74 5f 70 61 67 65 28 69 29 2c 20 22 50 75 72 63 68 61 73 65 20 4f 72 64 65 72 20 51 75 61 6e 74 69 74 79 22 29 29 20 2d 20 31 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_133{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,0b 00 0b 00 04 00 00 05 00 "
		
	strings :
		$a_00_0 = {44 65 76 65 6c 6f 70 65 64 20 62 79 20 4d 69 63 68 61 65 6c 20 45 69 66 66 6c 61 65 6e 64 65 72 20 2f 20 41 45 20 53 6f 66 74 77 61 72 65 20 53 6f 6c 75 74 69 6f 6e 73 } //02 00 
		$a_00_1 = {50 75 62 6c 69 63 20 74 4d 69 6c 65 73 74 6f 6e 65 73 28 35 30 30 30 29 20 41 73 20 54 6d 69 6c 65 73 74 6f 6e 65 } //02 00 
		$a_00_2 = {50 75 62 6c 69 63 20 6f 62 6a 50 50 54 20 41 73 20 4f 62 6a 65 63 74 20 27 50 6f 77 65 72 50 6f 69 6e 74 2e 41 70 70 6c 69 63 61 74 69 6f 6e } //02 00 
		$a_00_3 = {4d 73 67 42 6f 78 20 22 4e 6f 20 66 69 6c 65 73 20 73 65 6c 65 63 74 65 64 20 66 6f 72 20 61 6e 61 6c 79 73 69 73 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_134{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 70 69 63 6f 6c 6d 65 6d 20 3d 20 70 69 63 6f 6c 6c 69 73 74 2e 49 74 65 6d 28 22 57 53 4c 44 43 54 50 50 49 48 32 22 29 } //01 00 
		$a_00_1 = {73 54 61 67 6e 61 6d 65 20 3d 20 57 6f 72 6b 73 68 65 65 74 73 28 22 45 6e 74 72 79 20 53 68 65 65 74 22 29 2e 43 65 6c 6c 73 28 69 20 2b 20 34 2c 20 32 29 2e 54 65 78 74 } //01 00 
		$a_00_2 = {57 72 69 74 65 20 74 6f 20 53 65 63 6f 6e 64 61 79 20 50 49 20 53 65 72 76 65 72 } //01 00 
		$a_00_3 = {73 72 76 2e 50 49 50 6f 69 6e 74 73 28 73 54 61 67 6e 61 6d 65 29 2e 44 61 74 61 2e 55 70 64 61 74 65 56 61 6c 75 65 20 73 56 61 6c 75 65 2c 20 73 54 69 6d 65 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_135{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,0b 00 0b 00 04 00 00 05 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 61 73 61 70 2d 75 74 69 6c 69 74 69 65 73 2e 63 6f 6d } //02 00 
		$a_00_1 = {70 5f 73 50 61 74 68 20 3d 20 57 6f 72 6b 62 6f 6f 6b 73 28 22 41 53 41 50 20 55 74 69 6c 69 74 69 65 73 2e 78 6c 61 6d 22 29 2e 50 61 74 68 } //02 00 
		$a_00_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 22 27 41 53 41 50 20 55 74 69 6c 69 74 69 65 73 2e 78 6c 61 6d 27 21 41 53 41 50 52 75 6e 50 72 6f 63 5f 78 36 34 22 2c 20 6c 49 44 } //02 00 
		$a_00_3 = {53 75 62 20 41 53 41 50 52 69 62 62 6f 6e 5f 49 6e 69 74 69 61 6c 69 7a 65 28 72 69 62 62 6f 6e 20 41 73 20 49 52 69 62 62 6f 6e 55 49 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_136{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {50 72 69 76 61 74 65 20 53 75 62 20 54 4c 43 6f 6d 62 6f 42 6f 78 5f 43 68 61 6e 67 65 28 29 } //02 00 
		$a_00_1 = {50 72 69 76 61 74 65 20 53 75 62 20 52 65 6a 43 61 70 74 75 72 65 42 75 74 74 6f 6e 5f 43 6c 69 63 6b 28 29 } //02 00 
		$a_00_2 = {50 72 69 76 61 74 65 20 53 75 62 20 52 65 6a 45 6d 61 69 6c 54 78 74 42 6f 78 5f 43 68 61 6e 67 65 28 29 } //01 00 
		$a_00_3 = {41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 50 72 6f 64 75 63 74 69 76 69 74 79 22 29 2e 50 72 6f 74 65 63 74 20 50 61 73 73 77 6f 72 64 3a 3d 22 52 61 6d 65 73 65 73 22 } //01 00 
		$a_00_4 = {53 75 62 20 77 69 70 65 61 6c 6c 28 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_137{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 43 61 6c 63 75 6c 61 74 69 6f 6e 20 3d 20 78 6c 43 61 6c 63 75 6c 61 74 69 6f 6e 41 75 74 6f 6d 61 74 69 63 } //02 00 
		$a_00_1 = {49 66 20 62 6f 6f 6c 54 65 6d 70 20 3c 3e 20 53 52 41 63 74 69 76 61 74 69 6f 6e 42 6c 6f 63 6b 65 64 20 54 68 65 6e 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 43 61 6c 63 75 6c 61 74 65 46 75 6c 6c 52 65 62 75 69 6c 64 } //02 00 
		$a_00_2 = {54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 49 6e 70 75 74 22 29 2e 43 65 6c 6c 73 28 31 2c 20 31 29 2e 46 6f 72 6d 75 6c 61 20 3d 20 22 3d 53 74 6f 72 61 67 65 43 61 6c 63 28 4e 6f 77 29 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_138{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {5c 73 74 6c 66 69 6c 65 30 31 2e 69 6e 74 65 6c 6c 69 67 2e 6c 6f 63 61 6c 5c 44 41 54 41 5c 4c 45 47 41 43 59 5c 53 54 4c 2d 45 4e 47 32 5c 50 5f 44 72 69 76 65 5c 50 52 4f 50 4f 53 41 4c 5c 5a 53 79 73 74 65 6d 50 72 6f 70 } //02 00 
		$a_00_1 = {5c 77 63 6e 61 73 30 31 2e 69 6e 74 65 6c 6c 69 67 2e 6c 6f 63 61 6c 5c 69 6e 74 65 6c 6c 69 67 72 61 74 65 64 5c 44 65 70 74 5c 50 72 6f 6a 65 63 74 73 } //02 00 
		$a_00_2 = {5c 73 74 6c 66 69 6c 65 30 31 5c 44 41 54 41 5c 4c 45 47 41 43 59 5c 53 54 4c 2d 41 52 43 5c 53 74 2e 20 4c 6f 75 69 73 20 4c 65 67 61 63 79 20 50 72 6f 6a 65 63 74 20 44 69 72 65 63 74 6f 72 79 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_139{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 68 65 65 74 73 28 22 50 4c 2d 42 53 20 49 6d 70 61 63 74 22 29 2e 53 65 6c 65 63 74 } //01 00 
		$a_00_1 = {41 63 74 69 76 65 53 68 65 65 74 2e 4e 61 6d 65 20 3d 20 22 4f 50 45 58 20 49 6d 70 61 63 74 22 } //01 00 
		$a_00_2 = {63 75 72 72 65 6e 74 43 65 6c 6c 20 3d 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 57 6f 72 6b 73 68 65 65 74 73 28 22 4a 45 54 45 4d 50 4c 41 54 45 22 29 2e 43 65 6c 6c 73 28 61 63 74 69 76 65 43 65 6c 6c 52 6f 77 2c 20 31 31 29 2e 56 61 6c 75 65 } //01 00 
		$a_00_3 = {44 69 6d 20 4e 62 4c 69 67 6e 65 2c 20 44 65 72 4c 69 67 6e 65 2c 20 49 6e 73 65 72 74 4c 69 67 6e 65 20 41 73 20 53 74 72 69 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_140{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {50 72 69 76 61 74 65 20 50 72 6f 70 65 72 74 79 20 53 65 74 20 49 56 42 53 41 58 43 6f 6e 74 65 6e 74 48 61 6e 64 6c 65 72 5f 64 6f 63 75 6d 65 6e 74 4c 6f 63 61 74 6f 72 28 42 79 56 61 6c 20 52 48 53 20 41 73 20 4d 53 58 4d 4c 32 2e 49 56 42 53 41 58 4c 6f 63 61 74 6f 72 29 } //02 00 
		$a_00_1 = {45 72 72 2e 52 61 69 73 65 20 33 32 30 30 31 2c 20 22 49 56 42 53 41 58 43 6f 6e 74 65 6e 74 48 61 6e 64 6c 65 72 5f 73 74 61 72 74 45 6c 65 6d 65 6e 74 22 } //02 00 
		$a_00_2 = {50 72 69 76 61 74 65 20 53 75 62 20 49 56 42 53 41 58 43 6f 6e 74 65 6e 74 48 61 6e 64 6c 65 72 5f 73 74 61 72 74 44 6f 63 75 6d 65 6e 74 28 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_141{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {4d 73 67 42 6f 78 20 22 59 6f 75 20 68 61 76 65 20 73 65 6c 65 63 74 65 64 20 74 6f 20 72 75 6e 20 74 68 65 20 41 45 52 4d 4f 44 20 50 72 69 6d 65 20 6d 6f 64 65 6c 2c 20 62 75 74 20 74 68 65 20 53 63 72 65 65 6e 69 6e 67 20 54 6f 6f 6c 20 63 61 6e 6e 6f 74 22 } //01 00 
		$a_00_1 = {43 68 44 72 69 76 65 20 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 70 61 74 68 20 26 20 22 5c 53 43 52 45 45 4e 5c 41 45 52 4d 4f 44 50 52 49 4d 45 5c 22 } //01 00 
		$a_00_2 = {44 69 6d 20 41 45 52 4d 4f 44 50 52 49 4d 45 66 6f 6c 64 65 72 20 41 73 20 53 74 72 69 6e 67 } //01 00 
		$a_00_3 = {41 51 4d 41 55 20 53 43 52 45 45 4e 49 4e 47 20 54 4f 4f 4c } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_142{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 53 55 42 4b 45 59 20 3d 20 22 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 41 70 70 20 50 61 74 68 73 5c 49 54 47 44 6f 63 58 2e 65 78 65 22 } //02 00 
		$a_00_1 = {49 66 20 4c 65 66 74 28 56 61 6c 75 65 4e 61 6d 65 2c 20 56 61 6c 75 65 6c 65 6e 29 20 3d 20 22 49 54 47 44 6f 63 58 50 61 74 68 22 20 54 68 65 6e } //02 00 
		$a_00_2 = {53 65 74 20 76 69 73 41 64 64 4f 6e 20 3d 20 56 69 73 69 6f 2e 41 64 64 6f 6e 73 2e 41 64 64 28 73 74 72 41 70 70 50 61 74 68 20 26 20 22 49 54 47 44 6f 63 58 2e 65 78 65 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_143{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 6c 5f 63 6f 6e 74 72 6f 6c 20 3d 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 43 6f 6d 6d 61 6e 64 42 61 72 73 2e 46 69 6e 64 43 6f 6e 74 72 6f 6c 28 54 61 67 3a 3d 22 44 46 57 46 69 6c 74 65 72 22 29 } //01 00 
		$a_00_1 = {50 75 62 6c 69 63 20 53 75 62 20 73 65 74 46 69 6c 74 65 72 56 69 73 69 62 69 6c 69 74 79 28 69 56 69 73 69 62 6c 65 20 41 73 20 42 6f 6f 6c 65 61 6e 29 } //01 00 
		$a_00_2 = {53 65 74 20 6c 53 68 61 70 65 20 3d 20 6c 53 68 65 65 74 2e 53 68 61 70 65 73 28 22 46 69 6c 74 65 72 41 22 29 } //01 00 
		$a_00_3 = {53 65 74 20 6c 53 68 61 70 65 20 3d 20 6c 53 68 65 65 74 2e 53 68 61 70 65 73 28 22 49 6e 66 6f 41 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_144{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 73 75 62 45 78 65 63 5f 70 73 53 65 6c 65 63 74 49 6e 76 65 73 74 69 73 73 65 6d 65 6e 74 28 69 64 48 79 70 6f 74 68 65 73 65 20 41 73 20 53 74 72 69 6e 67 2c 20 69 64 46 6f 6e 64 73 20 41 73 20 53 74 72 69 6e 67 29 } //02 00 
		$a_00_1 = {50 61 72 61 6d 65 74 65 72 73 28 22 40 70 72 6f 70 49 6e 76 65 73 74 69 73 73 65 6d 65 6e 74 22 29 } //02 00 
		$a_00_2 = {50 61 72 61 6d 65 74 65 72 73 28 22 40 6c 62 48 79 70 6f 74 68 65 73 65 22 29 2e 56 61 6c 75 65 20 3d 20 69 64 48 79 70 6f 74 68 65 73 65 } //02 00 
		$a_00_3 = {50 61 72 61 6d 65 74 65 72 73 28 22 40 6c 62 53 43 50 49 22 29 2e 56 61 6c 75 65 20 3d 20 69 64 46 6f 6e 64 73 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_145{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 50 72 6f 70 65 72 74 79 20 47 65 74 20 49 74 65 6d 28 76 49 6e 64 65 78 20 41 73 20 56 61 72 69 61 6e 74 29 } //02 00 
		$a_00_1 = {44 69 6d 20 6f 62 6a 50 72 6f 70 65 72 74 69 65 73 20 41 73 20 4e 65 77 20 42 6e 65 56 42 41 50 72 6f 70 65 72 74 69 65 73 } //02 00 
		$a_00_2 = {50 75 62 6c 69 63 20 54 79 70 65 20 54 49 4d 45 5f 5a 4f 4e 45 5f 49 4e 46 4f 52 4d 41 54 49 4f 4e } //01 00 
		$a_00_3 = {50 72 69 76 61 74 65 20 6d 5f 63 6f 6c 53 68 65 65 74 73 20 41 73 20 4e 65 77 20 43 6f 6c 6c 65 63 74 69 6f 6e } //01 00 
		$a_00_4 = {50 72 69 76 61 74 65 20 6d 63 50 61 72 61 6d 65 74 65 72 73 20 41 73 20 43 6f 6c 6c 65 63 74 69 6f 6e } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_146{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 77 73 74 68 5f 50 72 6f 6a 65 74 20 3d 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 50 72 6f 6a 65 74 73 22 29 } //01 00 
		$a_00_1 = {53 65 74 20 77 73 74 68 5f 50 53 50 20 3d 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 53 75 69 76 69 5f 50 53 50 22 29 } //01 00 
		$a_00_2 = {53 65 74 20 77 73 74 68 5f 33 50 20 3d 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 53 75 69 76 69 5f 33 50 22 29 } //01 00 
		$a_00_3 = {6e 65 77 70 61 74 68 20 3d 20 45 6e 76 69 72 6f 6e 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 20 26 20 22 5c 44 72 69 76 65 73 4d 61 70 69 6e 67 2e 78 6c 73 78 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_147{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {43 6f 6e 73 74 20 52 65 6c 65 61 73 65 50 61 74 68 5f 73 69 6d 63 6f 31 44 42 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 5c 5c 77 69 74 74 61 67 2e 6e 65 74 5c 64 66 73 5c 67 72 6f 75 70 73 5c 49 6e 66 6f 5c 73 65 72 76 6f 66 69 6c 65 73 5c 73 69 6d 63 6f 5c 4d 6f 74 6f 72 44 61 74 61 62 61 73 65 5f 46 69 72 6d 77 61 72 65 5c 22 } //02 00 
		$a_00_1 = {66 69 6c 65 2e 77 72 69 74 65 6c 69 6e 65 20 28 22 3c 2f 4d 6f 74 6f 72 44 61 74 61 62 61 73 65 3e 22 29 } //02 00 
		$a_00_2 = {43 6f 6e 73 74 20 45 6e 64 61 74 46 69 6c 65 73 46 6f 6c 64 65 72 50 61 74 68 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 43 3a 5c 44 61 74 61 5c 54 65 6d 70 5c 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_148{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {46 69 6c 65 50 61 74 68 20 3d 20 22 47 3a 5c 54 45 41 4d 5c 4d 61 72 6b 65 74 20 4f 70 65 72 61 74 69 6f 6e 73 5c 53 54 4f 44 5c 4f 54 43 5c 50 72 69 63 65 20 44 61 74 61 62 61 73 65 20 56 34 2e 78 6c 73 62 22 } //01 00 
		$a_00_1 = {46 69 6c 65 53 74 72 20 3d 20 22 50 72 69 63 65 20 44 61 74 61 62 61 73 65 20 56 34 2e 78 6c 73 62 22 } //01 00 
		$a_00_2 = {4d 73 67 42 6f 78 20 22 50 6c 65 61 73 65 20 75 70 67 72 61 64 65 20 54 68 6f 6d 73 6f 6e 20 52 65 75 74 65 72 73 20 45 69 6b 6f 6e 20 45 78 63 65 6c 2e 22 } //01 00 
		$a_00_3 = {44 69 6d 20 47 46 53 45 4e 53 2c 20 47 46 53 4f 50 2c 20 45 43 45 4e 53 2c 20 45 43 4f 50 20 41 73 20 53 74 72 69 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_149{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {46 75 6e 63 74 69 6f 6e 20 53 51 4c 5f 41 4d 4f 53 5f 44 42 5f 47 65 74 53 65 74 74 69 6e 67 73 28 29 } //01 00 
		$a_00_1 = {44 61 74 61 62 61 73 65 4e 61 6d 65 20 3d 20 22 41 6d 6f 73 22 20 27 20 45 6e 74 65 72 20 79 6f 75 72 20 64 61 74 61 62 61 73 65 20 6e 61 6d 65 20 68 65 72 65 } //01 00 
		$a_00_2 = {46 75 6e 63 74 69 6f 6e 20 53 51 4c 5f 41 4d 4f 53 5f 44 42 5f 47 65 74 41 63 63 65 73 73 4c 65 76 65 6c 73 28 73 74 72 55 73 65 72 6e 61 6d 65 20 41 73 20 53 74 72 69 6e 67 29 } //01 00 
		$a_00_3 = {53 51 4c 5f 41 4d 4f 53 5f 44 42 5f 50 6f 70 75 6c 61 74 65 5f 53 50 45 43 49 41 4c 5f 43 4f 4e 44 5f 55 53 52 46 52 4d 20 3d 20 22 6e 6f 74 66 6f 75 6e 64 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_150{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {57 6f 72 6b 62 6f 6f 6b 73 28 22 45 43 5f 4c 69 73 74 5f 53 65 61 72 63 68 2e 78 6c 61 6d 22 29 } //01 00 
		$a_00_1 = {53 4f 55 52 43 45 3a 20 68 74 74 70 3a 2f 2f 73 74 61 63 6b 6f 76 65 72 66 6c 6f 77 2e 63 6f 6d 2f 71 75 65 73 74 69 6f 6e 73 2f 31 34 37 33 38 33 33 30 2f 6f 66 66 69 63 65 2d 32 30 31 33 2d 65 78 63 65 6c 2d 70 75 74 69 6e 63 6c 69 70 62 6f 61 72 64 2d 69 73 2d 64 69 66 66 65 72 65 6e 74 } //01 00 
		$a_00_2 = {54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 46 6f 6c 6c 6f 77 48 79 70 65 72 6c 69 6e 6b 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 65 78 63 65 6c 63 61 6d 70 75 73 2e 63 6f 6d 2f 6c 69 73 74 2d 73 65 61 72 63 68 2d 68 65 6c 70 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_151{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 74 72 48 65 6c 70 46 69 6c 65 20 3d 20 73 74 72 48 65 6c 70 46 69 6c 65 20 26 20 22 50 49 74 72 65 6e 64 58 4c 2e 48 4c 50 22 } //01 00 
		$a_00_1 = {50 75 62 6c 69 63 20 72 65 73 4f 62 6a 20 41 73 20 50 49 58 4c 54 57 49 5a 2e 52 65 73 6f 75 72 63 65 53 74 72 69 6e 67 73 } //01 00 
		$a_00_2 = {50 75 62 6c 69 63 20 57 69 74 68 45 76 65 6e 74 73 20 6d 5f 6f 62 6a 50 49 41 72 63 44 43 20 41 73 20 50 49 44 41 54 41 41 43 43 45 53 53 2e 50 49 41 72 63 68 69 76 65 44 61 74 61 } //01 00 
		$a_00_3 = {49 66 20 49 6e 53 74 72 28 61 54 72 61 63 65 73 28 6c 6e 67 49 6e 64 65 78 29 2e 44 61 74 61 53 6f 75 72 63 65 4e 61 6d 65 2c 20 22 50 49 45 78 63 65 6c 44 61 74 61 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_152{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 44 69 65 73 65 41 72 62 65 69 74 73 6d 61 70 70 65 22 } //02 00 
		$a_00_1 = {57 6f 72 6b 73 68 65 65 74 73 28 22 45 78 70 6f 72 74 5f 53 41 50 22 29 2e 43 65 6c 6c 73 2e 43 6c 65 61 72 } //02 00 
		$a_00_2 = {54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 43 6f 6e 74 69 66 6f 72 6d 22 29 2e 55 6e 70 72 6f 74 65 63 74 } //02 00 
		$a_00_3 = {54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 43 6f 6e 74 69 66 65 65 64 22 29 2e 55 6e 70 72 6f 74 65 63 74 } //02 00 
		$a_00_4 = {54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 41 69 72 43 6f 22 29 2e 55 6e 70 72 6f 74 65 63 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_153{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 52 45 47 5f 50 41 54 48 20 3d 20 22 53 6f 66 74 77 61 72 65 5c 4d 49 53 20 41 47 5c 50 4c 41 49 4e 5c 22 } //01 00 
		$a_00_1 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 43 5f 50 4c 41 49 4e 5f 56 42 41 57 4b 42 20 3d 20 22 41 58 4c 43 2e 58 4c 41 22 } //01 00 
		$a_00_2 = {4f 6e 41 63 74 69 6f 6e 20 3d 20 22 4d 69 73 2e 50 6c 61 69 6e 2e 41 63 74 69 6f 6e 73 44 72 69 6c 6c 54 68 72 6f 75 67 68 2e 78 6c 61 21 45 76 61 6c 50 6f 70 55 70 41 63 74 69 6f 6e 73 22 } //01 00 
		$a_00_3 = {49 66 20 54 72 69 6d 28 73 4d 44 58 29 20 3d 20 22 22 20 54 68 65 6e 20 73 4d 44 58 20 3d 20 42 75 69 6c 64 44 72 69 6c 6c 54 68 72 6f 75 67 68 4d 44 58 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_154{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {66 69 6c 65 50 61 74 68 20 3d 20 52 61 6e 67 65 28 22 43 33 22 29 2e 56 61 6c 75 65 20 26 20 22 5c 69 6b 6f 75 74 6f 64 6f 6b 65 5f 22 20 26 20 6e 65 6e 64 6f 20 26 20 22 2e 78 6c 73 78 22 } //01 00 
		$a_00_1 = {66 69 6c 65 50 61 74 68 32 20 3d 20 77 73 2e 43 65 6c 6c 73 28 34 2c 20 32 29 2e 56 61 6c 75 65 20 26 20 22 5c 62 61 63 6b 75 70 5c 69 6b 6f 75 74 6f 64 6f 6b 65 5f 22 20 26 20 6e 65 6e 64 6f 28 69 29 20 26 20 22 5f 62 61 6b 2e 78 6c 73 78 22 } //01 00 
		$a_00_2 = {46 75 6e 63 74 69 6f 6e 20 67 65 74 5f 6e 65 6e 64 6f 28 79 6d 64 29 } //01 00 
		$a_00_3 = {44 69 6d 20 6b 77 31 2c 20 6b 77 32 2c 20 6b 77 33 2c 20 64 66 2c 20 64 65 20 41 73 20 53 74 72 69 6e 67 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_155{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 77 73 20 3d 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 52 6f 73 74 65 72 22 29 } //02 00 
		$a_00_1 = {73 43 6f 6d 70 61 72 65 20 3d 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 52 6f 73 74 65 72 22 29 2e 52 61 6e 67 65 28 63 53 74 61 72 74 20 26 20 72 44 61 74 65 72 6f 77 29 2e 56 61 6c 75 65 } //02 00 
		$a_00_2 = {4d 65 2e 74 78 74 53 74 61 72 74 2e 56 61 6c 75 65 20 3d 20 46 6f 72 6d 61 74 28 66 72 6d 5f 44 61 74 65 53 65 6c 65 63 74 2e 54 61 67 2c 20 22 64 64 2d 6d 6d 6d 2d 79 79 79 79 22 29 } //02 00 
		$a_00_3 = {4d 73 67 42 6f 78 20 28 22 53 68 69 66 74 20 68 61 73 20 62 65 65 6e 20 73 61 76 65 64 2e 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_156{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,0a 00 0a 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 61 61 61 52 75 74 69 6e 65 73 5a 49 50 22 } //02 00 
		$a_00_1 = {44 69 6d 20 46 69 74 5a 69 70 20 41 73 20 56 61 72 69 61 6e 74 } //02 00 
		$a_00_2 = {46 69 74 5a 69 70 20 3d 20 43 65 6c 44 65 4e 6f 6d 42 61 73 65 28 22 5a 69 70 4f 72 69 22 29 } //02 00 
		$a_00_3 = {44 65 73 63 6f 6d 70 72 69 6d 69 72 5a 49 50 20 46 69 74 5a 69 70 2c 20 43 65 6c 44 65 4e 6f 6d 42 61 73 65 28 22 44 69 72 44 65 73 22 29 20 27 20 22 63 3a 5c 74 73 74 5c 61 2e 7a 69 70 22 } //02 00 
		$a_00_4 = {4d 73 67 42 6f 78 20 4e 6f 6d 5a 49 50 6e 45 73 73 69 6d 28 46 69 74 5a 69 70 2c 20 43 65 6c 44 65 4e 6f 6d 42 61 73 65 28 22 6e 75 6d 22 29 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_157{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,09 00 09 00 0e 00 00 03 00 "
		
	strings :
		$a_00_0 = {73 6f 6c 76 65 72 33 32 2e 64 6c 6c } //01 00 
		$a_00_1 = {73 6f 6c 76 65 72 6f 6b } //01 00 
		$a_00_2 = {73 6f 6c 76 65 72 6f 6b 64 69 61 6c 6f 67 } //01 00 
		$a_00_3 = {73 6f 6c 76 65 72 63 6f 64 65 } //01 00 
		$a_00_4 = {73 6f 6c 76 65 72 63 61 6c 6c 73 } //01 00 
		$a_00_5 = {73 6f 6c 76 65 72 73 6f 6c 76 65 } //01 00 
		$a_00_6 = {73 6f 6c 76 65 72 61 64 64 } //01 00 
		$a_00_7 = {73 6f 6c 76 65 72 63 68 61 6e 67 65 } //01 00 
		$a_00_8 = {73 6f 6c 76 65 72 64 65 6c 65 74 65 } //01 00 
		$a_00_9 = {73 6f 6c 76 65 72 66 69 6e 69 73 68 } //01 00 
		$a_00_10 = {73 6f 6c 76 65 72 67 65 74 } //01 00 
		$a_00_11 = {73 6f 6c 76 65 72 6f 70 74 69 6f 6e 73 } //01 00 
		$a_00_12 = {73 6f 6c 76 65 72 72 65 73 65 74 } //01 00 
		$a_00_13 = {64 6c 67 73 6f 6c 76 65 72 70 61 72 61 6d 65 74 65 72 73 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_158{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {50 61 74 74 65 72 6e 20 3d 20 78 6c 53 6f 6c 69 64 } //02 00 
		$a_01_1 = {50 61 74 74 65 72 6e 43 6f 6c 6f 72 49 6e 64 65 78 20 3d 20 78 6c 41 75 74 6f 6d 61 74 69 63 } //ce ff 
		$a_00_2 = {68 74 74 70 73 3a 2f 2f 73 69 74 65 73 2e 74 68 65 77 65 73 74 70 61 63 67 72 6f 75 70 2e 63 6f 6d 2e 61 75 2f 73 69 74 65 73 2f 54 53 36 35 37 2f 57 41 53 50 2f 50 75 62 6c 69 73 68 69 6e 67 49 6d 61 67 65 73 2f 57 41 53 50 25 32 30 46 54 45 25 32 30 46 6f 72 65 63 61 73 74 25 32 30 49 6d 70 6f 72 74 25 32 30 54 75 74 6f 72 69 61 6c 73 2f 57 41 53 50 25 32 30 46 54 45 25 32 30 46 6f 72 65 63 61 73 74 25 32 30 49 6d 70 6f 72 74 25 32 30 54 75 74 6f 72 69 61 6c 73 2e 6d 70 34 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_159{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 53 55 42 4b 45 59 20 3d 20 22 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 41 70 70 20 50 61 74 68 73 5c 49 54 47 44 6f 63 58 2e 65 78 65 22 } //02 00 
		$a_00_1 = {56 69 73 69 6f 2e 41 64 64 6f 6e 73 2e 49 74 65 6d 28 73 74 72 41 70 70 50 61 74 68 20 26 20 22 49 54 47 44 6f 63 58 2e 65 78 65 22 29 2e 52 75 6e 20 28 22 53 70 6c 61 73 68 22 29 } //02 00 
		$a_00_2 = {43 68 6f 69 63 65 20 3d 20 4d 73 67 42 6f 78 28 73 74 72 4d 73 67 2c 20 76 62 59 65 73 4e 6f 20 2b 20 76 62 45 78 63 6c 61 6d 61 74 69 6f 6e 2c 20 22 49 54 47 20 44 65 73 69 67 6e 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_160{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {43 6f 6e 73 74 20 41 70 69 50 72 65 66 69 78 50 6d 74 50 72 6f 64 73 20 3d 20 22 68 74 74 70 73 3a 2f 2f 73 70 32 30 31 33 2e 6d 79 61 74 6f 73 2e 6e 65 74 2f 6f 72 67 61 6e 69 7a 61 74 69 6f 6e 2f 67 62 75 2f 77 6c 2f 65 77 6c 2f 63 6f 6f 2f 50 61 79 6d 65 6e 74 73 25 32 30 70 72 6f 64 75 63 74 73 2f 5f 61 70 69 22 } //02 00 
		$a_00_1 = {68 74 74 70 73 3a 2f 2f 61 63 63 2d 6a 69 72 61 2e 77 6f 72 6c 64 6c 69 6e 65 2e 63 6f 6d } //02 00 
		$a_00_2 = {68 74 74 70 73 3a 2f 2f 63 68 61 6c 6c 65 6e 67 65 2e 70 61 79 31 2d 74 65 73 74 2e 64 65 2f 63 61 6c 63 75 6c 6f 6e 3f 72 73 6c 74 3d } //02 00 
		$a_00_3 = {69 73 73 75 65 4b 65 79 20 3d 20 22 45 32 45 43 44 2d 32 38 32 39 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_161{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 45 78 70 6f 72 74 44 61 74 61 4f 62 6a 65 63 74 54 6f 58 4d 4c 28 63 6f 6c 52 69 73 6b 44 61 74 61 20 41 73 20 63 6c 73 52 69 73 6b 44 61 74 61 43 6f 6c 2c 20 6d 66 46 69 6c 74 65 72 20 41 73 20 53 74 72 69 6e 67 29 } //01 00 
		$a_00_1 = {2e 49 64 20 3d 20 4c 43 61 73 65 28 72 69 73 6b 44 61 74 61 2e 4d 61 69 6e 46 75 6e 63 74 69 6f 6e 49 44 20 26 20 22 3b 22 20 26 20 72 69 73 6b 44 61 74 61 2e 53 75 62 46 75 6e 63 74 69 6f 6e 20 26 20 22 3b 22 20 26 20 63 75 72 72 52 6f 77 29 } //01 00 
		$a_00_2 = {63 6f 6c 52 69 73 6b 44 61 74 61 2e 52 65 73 6f 6c 76 65 52 69 73 6b 20 63 6f 6c 52 69 73 6b 44 61 74 61 2e 49 74 65 6d 73 2e 69 74 65 6d 28 69 50 6f 73 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_162{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 53 75 62 20 4d 6f 64 46 69 6c 65 54 6f 6f 6c 5f 53 65 74 46 6f 72 6d 61 74 28 52 47 20 41 73 20 52 61 6e 67 65 2c 20 46 47 20 41 73 20 49 6e 74 65 67 65 72 29 } //01 00 
		$a_00_1 = {50 72 69 76 61 74 65 20 46 75 6e 63 74 69 6f 6e 20 63 6b 5f 46 49 4c 45 4e 41 4d 45 5f 58 4c 53 5f 4a 28 52 47 20 41 73 20 52 61 6e 67 65 29 20 41 73 20 42 6f 6f 6c 65 61 6e } //01 00 
		$a_00_2 = {49 66 20 63 6f 5f 43 4b 44 41 54 41 4e 41 4d 45 20 3d 20 22 46 45 48 5f 53 54 41 54 44 42 49 4e 46 22 20 54 68 65 6e } //01 00 
		$a_00_3 = {43 61 6c 6c 20 61 64 64 44 61 74 61 43 6b 43 6f 6c 28 43 65 6c 6c 73 28 6d 79 6c 69 6e 65 2c 20 63 6f 5f 44 61 74 61 5f 43 4b 5f 63 6f 6c 29 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_163{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {73 6f 66 74 77 61 72 65 5c 64 61 74 61 73 74 72 65 61 6d 5c 64 61 74 61 73 74 72 65 61 6d 20 61 64 76 61 6e 63 65 5c 70 65 72 73 69 73 74 65 6e 63 65 5c 70 6f 77 65 72 73 65 61 72 63 68 } //02 00 
		$a_00_1 = {73 6f 66 74 77 61 72 65 5c 64 61 74 61 73 74 72 65 61 6d 5c 64 61 74 61 73 74 72 65 61 6d 20 61 64 76 61 6e 63 65 5c 6d 69 73 63 } //02 00 
		$a_00_2 = {73 6f 66 74 77 61 72 65 5c 64 61 74 61 73 74 72 65 61 6d 5c 64 61 74 61 73 74 72 65 61 6d 20 61 64 76 61 6e 63 65 5c 66 69 6c 65 73 } //02 00 
		$a_00_3 = {68 74 74 70 3a 2f 2f 70 72 6f 64 75 63 74 2e 64 61 74 61 73 74 72 65 61 6d 2e 63 6f 6d 2f 75 63 69 2f } //02 00 
		$a_00_4 = {61 64 76 61 6e 63 65 20 66 6f 72 20 6f 66 66 69 63 65 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_164{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {41 63 74 69 76 65 53 68 65 65 74 2e 43 65 6c 6c 73 28 6c 61 73 74 72 6f 77 2c 20 31 29 2e 56 61 6c 75 65 20 3d 20 22 41 76 61 79 61 20 49 6e 64 69 61 20 4c 69 6d 69 74 65 64 22 } //02 00 
		$a_00_1 = {41 63 74 69 76 65 53 68 65 65 74 2e 43 65 6c 6c 73 28 6c 61 73 74 72 6f 77 2c 20 31 29 2e 56 61 6c 75 65 20 3d 20 22 52 53 41 32 20 53 65 63 75 72 69 74 79 20 26 20 52 69 73 6b 20 49 72 65 6c 61 6e 64 20 4c 69 6d 69 74 65 64 22 } //02 00 
		$a_00_2 = {41 63 74 69 76 65 53 68 65 65 74 2e 43 65 6c 6c 73 28 6c 61 73 74 72 6f 77 2c 20 31 29 2e 56 61 6c 75 65 20 3d 20 22 50 75 72 65 20 53 74 6f 72 61 67 65 20 49 6e 74 65 72 6e 61 74 69 6f 6e 61 6c 20 4c 69 6d 69 74 65 64 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_165{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {52 61 6e 67 65 28 22 4d 41 53 5b 5b 43 65 6e 74 72 61 6c 20 2f 20 4c 6f 63 61 6c 20 43 6f 6c 6c 65 63 74 69 6f 6e 5d 3a 5b 43 6f 6c 6c 65 63 74 69 6f 6e 20 4c 6f 63 61 74 69 6f 6e 5d 5d 22 29 } //02 00 
		$a_00_1 = {52 61 6e 67 65 28 22 4d 41 53 5b 5b 4c 6f 63 61 6c 20 49 6e 73 75 72 65 72 5d 3a 5b 49 6e 74 72 61 63 6f 6d 70 61 6e 79 20 50 6f 6c 69 63 79 20 2f 20 52 65 69 6e 73 75 72 61 6e 63 65 20 41 67 72 65 65 6d 65 6e 74 20 4e 75 6d 62 65 72 5d 5d 22 29 } //02 00 
		$a_00_2 = {52 61 6e 67 65 28 22 4d 41 53 5b 5b 4c 6f 63 61 6c 20 50 6f 6c 69 63 79 20 43 75 72 72 65 6e 63 79 5d 3a 5b 4c 6f 63 61 6c 20 50 6f 6c 69 63 79 20 43 75 72 72 65 6e 63 79 20 52 4f 45 5d 5d 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_166{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {50 72 69 76 61 74 65 20 43 6f 6e 73 74 20 77 6f 72 6b 69 6e 67 46 6f 6c 64 65 72 20 3d 20 22 43 3a 5c 55 74 69 6c 5c 66 72 65 65 6a 65 74 5c 22 } //01 00 
		$a_00_1 = {50 72 69 76 61 74 65 20 43 6f 6e 73 74 20 66 72 65 65 4a 65 74 46 6f 6c 64 65 72 20 3d 20 22 46 72 65 65 4a 65 74 5c 72 65 73 6f 75 72 63 65 73 5c 22 } //01 00 
		$a_00_2 = {65 78 65 63 75 74 61 62 6c 65 73 5f 6c 6f 63 61 74 69 6f 6e 20 3d 20 73 74 72 44 6f 63 75 6d 65 6e 74 73 20 26 20 22 5c 22 20 26 20 66 72 65 65 4a 65 74 46 6f 6c 64 65 72 } //01 00 
		$a_00_3 = {66 69 6c 65 50 61 74 68 20 3d 20 77 6f 72 6b 69 6e 67 46 6f 6c 64 65 72 20 26 20 62 70 32 64 69 6d 46 69 6c 65 4e 61 6d 65 20 26 20 22 2e 46 53 54 45 49 4e 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_167{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {52 61 6e 67 65 28 33 29 20 3d 20 62 75 69 6c 64 50 68 61 73 65 43 6f 6d 62 6f 2e 54 65 78 74 } //01 00 
		$a_00_1 = {64 65 76 69 63 65 2e 41 64 64 20 22 73 73 64 56 65 6e 64 6f 72 22 2c 20 2e 52 61 6e 67 65 28 63 6f 6c 75 6d 6e 4d 61 70 28 22 53 53 44 20 56 65 6e 64 6f 72 22 29 29 } //01 00 
		$a_00_2 = {64 65 76 69 63 65 2e 41 64 64 20 22 73 6b 75 22 2c 20 2e 52 61 6e 67 65 28 63 6f 6c 75 6d 6e 4d 61 70 28 22 53 4b 55 22 29 29 } //01 00 
		$a_00_3 = {50 72 69 76 61 74 65 20 46 75 6e 63 74 69 6f 6e 20 72 6f 77 54 6f 44 69 63 74 28 72 6f 77 20 41 73 20 4c 69 73 74 52 6f 77 2c 20 63 6f 6c 75 6d 6e 4d 61 70 20 41 73 20 44 69 63 74 69 6f 6e 61 72 79 29 20 41 73 20 44 69 63 74 69 6f 6e 61 72 79 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_168{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 4d 75 6e 69 42 6c 6f 6f 6d 62 65 72 67 28 63 75 73 69 70 20 41 73 20 53 74 72 69 6e 67 29 } //01 00 
		$a_00_1 = {53 65 74 20 72 57 69 6e 64 6f 77 73 20 3d 20 57 6f 72 6b 62 6f 6f 6b 73 28 61 64 64 69 6e 5f 6e 61 6d 65 29 2e 53 68 65 65 74 73 28 22 56 61 6c 75 65 73 22 29 2e 52 61 6e 67 65 28 22 42 6c 6f 6f 6d 62 65 72 67 57 69 6e 64 6f 77 73 22 29 } //01 00 
		$a_00_2 = {53 75 62 20 4d 75 6e 69 42 6c 6f 6f 6d 62 65 72 67 53 65 6e 64 42 6f 6e 64 28 63 75 73 69 70 20 41 73 20 53 74 72 69 6e 67 29 } //01 00 
		$a_00_3 = {50 75 62 6c 69 63 20 53 75 62 20 4d 75 6e 69 42 6c 6f 6f 6d 62 65 72 67 54 43 28 6d 61 73 74 65 72 54 69 63 6b 65 74 4e 75 6d 62 65 72 20 41 73 20 53 74 72 69 6e 67 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_169{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 62 62 2e 43 61 70 74 69 6f 6e 20 3d 20 22 46 61 7a 53 70 69 65 67 65 6c 2d 4c 6f 67 } //01 00 
		$a_00_1 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 43 6f 6d 6d 61 6e 64 42 61 72 73 28 22 57 6f 72 6b 73 68 65 65 74 20 4d 65 6e 75 20 42 61 72 22 29 2e 43 6f 6e 74 72 6f 6c 73 28 22 45 78 74 72 61 73 22 29 2e 43 6f 6e 74 72 6f 6c 73 28 22 46 41 5a 20 53 70 69 65 67 65 6c 22 29 2e 44 65 6c 65 74 65 } //01 00 
		$a_00_2 = {53 74 72 69 6e 67 32 46 69 6c 65 20 46 61 7a 43 6f 6e 66 69 67 46 69 6c 65 2c 20 74 78 74 49 6e 69 66 69 6c 65 2e 54 65 78 74 2c 20 46 61 6c 73 65 } //01 00 
		$a_00_3 = {46 61 7a 53 70 69 65 67 65 6c 41 75 73 67 61 62 65 20 3d 20 63 41 75 73 67 61 62 65 53 74 65 6c 6c 65 6e 6d 61 72 6b 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_170{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {4b 72 6f 6e 65 73 44 61 74 61 49 6e 74 65 72 66 61 63 65 5f 4b 34 34 33 33 39 30 5f 42 6c 6f 77 2d 4d 6f 75 6c 64 65 72 5f 43 6f 6d 6d 69 73 73 69 6f 6e 69 6e 67 2e 78 6c 73 } //01 00 
		$a_00_1 = {50 72 69 76 61 74 65 20 43 6f 6e 73 74 20 6d 6f 64 75 6c 6e 61 6d 65 20 3d 20 22 55 46 5f 43 68 65 63 6b 4b 6f 6d 4e 6f 4d 61 6e 75 61 6c 22 } //01 00 
		$a_00_2 = {50 72 69 76 61 74 65 20 53 75 62 20 54 78 74 5f 4b 6f 6d 4e 6f 5f 41 66 74 65 72 55 70 64 61 74 65 28 29 } //01 00 
		$a_00_3 = {43 61 6c 6c 20 46 6f 72 6d 61 74 53 68 65 65 74 45 6e 74 72 69 65 73 28 73 68 74 2c 20 72 6e 67 53 2e 52 61 6e 67 65 2c 20 22 46 54 5f 57 68 69 74 65 53 74 61 6e 64 61 72 73 22 2c 20 46 61 6c 73 65 2c 20 54 72 75 65 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_171{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 62 6f 6f 6b 20 3d 20 77 62 2e 57 6f 72 6b 62 6f 6f 6b 73 2e 41 64 64 28 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 50 61 74 68 20 26 20 22 5c 73 70 69 6e 6e 65 72 2e 78 6c 73 6d 22 29 } //01 00 
		$a_00_1 = {4f 70 65 6e 20 73 65 63 6f 6e 64 61 72 79 20 73 68 65 65 74 20 74 6f 20 73 68 6f 77 20 73 70 69 6e 6e 65 72 } //01 00 
		$a_00_2 = {53 65 74 20 6f 52 6e 67 20 3d 20 49 6e 74 65 72 73 65 63 74 28 53 65 6c 65 63 74 69 6f 6e 2c 20 53 65 6c 65 63 74 69 6f 6e 2e 50 61 72 65 6e 74 2e 55 73 65 64 52 61 6e 67 65 } //01 00 
		$a_00_3 = {49 66 20 63 79 46 72 65 71 75 65 6e 63 79 20 54 68 65 6e 20 4d 69 63 72 6f 54 69 6d 65 72 20 3d 20 63 79 54 69 63 6b 73 31 20 2f 20 63 79 46 72 65 71 75 65 6e 63 79 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_172{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {44 61 74 61 2e 54 61 62 6c 65 4e 61 6d 65 20 3d 20 22 41 67 49 6e 70 75 74 44 61 74 61 22 } //01 00 
		$a_00_1 = {66 69 65 6c 64 73 2e 41 70 70 65 6e 64 20 22 4c 69 76 65 73 74 6f 63 6b 50 72 6f 64 75 63 74 73 41 63 63 72 75 61 6c 41 64 6a 75 73 74 6d 65 6e 74 22 } //01 00 
		$a_00_2 = {66 69 65 6c 64 73 2e 41 70 70 65 6e 64 20 22 43 72 6f 70 49 6e 73 75 72 61 6e 63 65 41 6e 64 44 69 73 61 73 74 65 72 50 72 6f 63 65 65 64 73 22 } //01 00 
		$a_00_3 = {49 6e 76 65 73 74 6d 65 6e 74 49 6e 47 72 6f 77 69 6e 67 43 72 6f 70 73 41 63 63 72 75 61 6c 41 64 6a 75 73 74 6d 65 6e 74 } //01 00 
		$a_00_4 = {41 63 63 75 6d 75 6c 61 74 65 64 44 65 70 72 65 63 69 61 74 69 6f 6e 4d 61 63 68 69 6e 65 72 79 45 71 75 69 70 6d 65 6e 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_173{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,0a 00 0a 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {50 75 62 6c 69 63 20 54 79 70 65 20 74 4d 69 6c 65 73 74 6f 6e 65 } //02 00 
		$a_01_1 = {50 75 62 6c 69 63 20 53 75 62 20 75 70 64 61 74 65 5f 54 69 6d 65 6c 69 6e 65 28 73 74 61 72 74 44 61 74 65 2c 20 6e 65 77 54 6c 50 65 72 69 6f 64 2c 20 74 6c 57 65 65 6b 73 20 41 73 20 42 6f 6f 6c 65 61 6e 2c 20 6e 65 77 50 6f 6f 6c 43 6f 6c 73 29 } //01 00 
		$a_01_2 = {46 75 6e 63 74 69 6f 6e 20 52 44 50 5f 50 52 4e 73 28 29 20 41 73 20 56 61 72 69 61 6e 74 } //01 00 
		$a_01_3 = {46 75 6e 63 74 69 6f 6e 20 61 62 62 72 65 76 69 61 74 65 5f 4d 53 5f 4e 61 6d 65 28 6d 73 4e 61 6d 65 29 } //01 00 
		$a_01_4 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 74 72 69 6d 54 69 6d 65 28 64 61 74 65 5f 77 69 74 68 5f 74 69 6d 65 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_174{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 04 00 00 02 00 "
		
	strings :
		$a_00_0 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 6d 64 41 64 64 5f 45 64 69 74 5f 56 69 65 77 22 } //02 00 
		$a_00_1 = {53 65 74 20 77 4d 61 72 6b 20 3d 20 61 75 64 69 74 65 64 53 68 65 65 74 2e 53 68 61 70 65 73 28 22 44 72 61 66 74 57 61 74 65 72 6d 61 72 6b 22 29 } //02 00 
		$a_00_2 = {47 65 74 53 65 72 76 65 72 54 69 6d 65 20 3d 20 67 65 74 52 65 6d 6f 74 65 54 4f 44 28 22 5c 5c 6e 69 2d 63 72 2d 73 76 63 2d 64 63 31 22 29 } //02 00 
		$a_00_3 = {53 65 74 20 64 61 74 61 46 69 65 6c 64 43 6f 6c 73 20 3d 20 6e 65 77 41 75 64 69 74 53 68 74 2e 43 6f 6c 75 6d 6e 73 28 63 6f 6c 50 61 72 61 6d 31 29 2e 52 65 73 69 7a 65 28 43 6f 6c 75 6d 6e 53 69 7a 65 3a 3d 6e 75 6d 43 6f 6c 73 20 2a 20 32 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_175{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 53 50 4d 53 58 44 61 74 61 46 69 6c 65 4e 61 6d 65 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 46 4f 44 4d 63 6f 6d 6d 4d 53 58 44 61 74 61 2e 78 6c 73 78 22 } //02 00 
		$a_00_1 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 74 6f 6f 6c 54 69 74 6c 65 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 53 70 6f 74 6c 69 67 68 74 20 2d 20 47 46 4f 20 41 75 74 6f 6d 61 74 65 64 20 43 6f 6d 6d 20 54 6f 6f 6c 22 } //02 00 
		$a_00_2 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 4c 49 52 53 65 72 76 65 72 4e 61 6d 65 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 6d 62 6f 64 65 73 79 6e 61 70 73 65 2d 6f 6e 64 65 6d 61 6e 64 2e 53 71 6c 2e 61 7a 75 72 65 73 79 6e 61 70 73 65 2e 6e 65 74 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_176{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {41 70 70 6c 69 63 61 74 69 6f 6e 20 20 4e 61 6d 65 3a 20 20 56 6f 79 61 67 65 72 50 6c 61 6e 20 44 69 61 67 72 61 6d 20 50 72 69 6e 74 20 4d 61 63 72 6f 73 } //01 00 
		$a_00_1 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 50 75 62 4d 61 63 72 6f 73 22 } //01 00 
		$a_00_2 = {55 4b 3a 31 32 30 31 34 39 39 31 20 2d 20 52 65 6d 6f 76 65 64 20 53 61 76 65 44 6f 63 75 6d 65 6e 74 20 63 61 6c 6c 20 61 73 20 69 74 20 77 69 6c 6c 20 62 65 20 73 61 76 65 64 20 66 72 6f 6d 20 56 50 52 49 31 33 35 30 2e 64 6c 6c } //01 00 
		$a_00_3 = {50 72 69 76 61 74 65 20 43 6f 6e 73 74 20 6d 63 4d 6f 64 75 6c 65 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 44 69 61 67 72 61 6d 20 50 72 69 6e 74 20 4d 61 63 72 6f 73 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_177{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 53 75 62 20 73 6f 72 74 42 52 42 53 68 65 65 74 28 73 68 65 65 74 53 65 6c 65 63 74 65 64 20 41 73 20 57 6f 72 6b 73 68 65 65 74 2c 20 63 65 6c 6c 53 65 6c 65 63 74 65 64 20 41 73 20 52 61 6e 67 65 2c 20 73 6f 72 74 44 69 72 65 63 74 69 6f 6e 20 41 73 20 58 6c 53 6f 72 74 4f 72 64 65 72 29 } //02 00 
		$a_00_1 = {49 66 20 73 68 65 65 74 53 65 6c 65 63 74 65 64 2e 6e 61 6d 65 20 3d 20 22 57 6f 57 20 44 69 67 65 73 74 22 20 54 68 65 6e } //02 00 
		$a_00_2 = {53 65 74 20 63 6f 6c 75 6d 6e 73 42 79 48 65 61 64 65 72 20 3d 20 57 6f 72 6b 62 65 6e 63 68 55 46 2e 61 6e 6e 6f 74 61 74 69 6f 6e 73 41 70 70 2e 72 65 76 65 6e 75 65 52 65 70 6f 72 74 43 6f 6c 75 6d 6e 73 42 79 48 65 61 64 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_178{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {43 6f 6e 73 74 20 53 45 52 56 4c 45 54 5f 50 41 54 48 20 3d 20 22 68 74 74 70 3a 2f 2f 63 72 2d 73 76 63 2d 66 69 6e 31 2e 70 68 61 72 6d 73 2d 73 65 72 76 69 63 65 73 2e 63 6f 6d 3a 38 30 30 30 2f 6f 61 5f 73 65 72 76 6c 65 74 73 2f 22 } //01 00 
		$a_00_1 = {47 65 6e 65 72 61 74 65 64 3a 42 6e 65 4f 41 45 78 63 65 6c } //01 00 
		$a_00_2 = {41 64 64 42 6e 65 4d 73 67 20 42 4e 45 5f 45 52 52 4f 52 2c 20 22 42 6e 65 55 70 6c 6f 61 64 42 65 67 69 6e 22 2c 20 22 43 6f 75 6c 64 6e 27 74 20 43 72 65 61 74 65 20 61 20 44 4f 4d 20 44 6f 63 75 6d 65 6e 74 22 } //01 00 
		$a_00_3 = {43 6f 6e 73 74 20 44 45 42 55 47 5f 44 4f 43 55 4d 45 4e 54 20 3d 20 22 63 3a 5c 42 6e 65 44 65 62 75 67 2d 44 6f 63 75 6d 65 6e 74 2e 78 6d 6c 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_179{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {49 66 20 6d 75 2e 43 61 70 74 69 6f 6e 20 3d 20 22 26 41 73 70 65 6e 20 50 72 6f 70 65 72 74 69 65 73 22 20 54 68 65 6e } //01 00 
		$a_00_1 = {50 75 62 6c 69 63 20 67 5f 41 73 70 65 6e 50 72 6f 70 65 72 74 69 65 73 53 74 61 72 74 75 70 64 69 72 20 41 73 20 53 74 72 69 6e 67 } //01 00 
		$a_00_2 = {73 74 72 50 61 74 68 2c 20 70 73 7a 54 69 74 6c 65 3a 3d 22 53 65 6c 65 63 74 20 41 73 70 65 6e 20 50 72 6f 70 65 72 74 69 65 73 20 77 6f 72 6b 69 6e 67 20 66 6f 6c 64 65 72 3a 22 29 } //01 00 
		$a_00_3 = {53 65 74 20 6d 6f 62 6a 48 61 70 70 48 61 70 70 49 70 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 41 73 70 65 6e 50 72 6f 70 65 72 74 69 65 73 2e 44 6f 63 75 6d 65 6e 74 2e 22 20 2b 20 67 5f 4d 4d 56 65 72 73 69 6f 6e 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_180{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {2e 4f 70 65 6e 20 22 50 4f 53 54 22 2c 20 22 68 74 74 70 3a 2f 2f 76 69 73 61 73 63 72 73 2e 66 63 6f 2e 67 73 69 2e 67 6f 76 2e 75 6b 2f 55 4b 43 52 53 2f 55 4b 43 52 53 4d 65 6e 75 2f 4d 45 4e 55 5f 6c 6f 67 69 6e 2e 61 73 70 22 } //02 00 
		$a_00_1 = {54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 46 6f 6c 6c 6f 77 48 79 70 65 72 6c 69 6e 6b 20 50 4f 49 53 45 5f 6f 72 5f 54 53 5f 4c 69 6e 6b 20 26 20 22 5c 64 61 74 61 20 61 6e 61 6c 79 73 69 73 20 74 65 61 6d 5c 4e 65 77 20 44 41 20 54 65 61 6d 20 53 74 72 75 63 74 75 72 65 5c 57 52 20 57 6f 72 6b 20 52 65 71 75 65 73 74 73 5c 52 65 67 75 6c 61 72 5c 57 52 31 38 36 39 } //02 00 
		$a_00_2 = {6f 62 6a 4f 4c 2e 47 65 74 4e 61 6d 65 73 70 61 63 65 28 22 4d 41 50 49 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_181{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {57 6f 72 6b 62 6f 6f 6b 73 2e 4f 70 65 6e 20 46 69 6c 65 6e 61 6d 65 3a 3d 73 74 72 50 65 72 45 69 6e 73 74 20 26 20 22 45 49 4e 53 54 45 4c 4c 55 4e 47 45 4e 2e 78 6c 73 78 22 } //01 00 
		$a_00_1 = {73 74 72 53 51 4c 20 3d 20 22 53 45 4c 45 43 54 20 47 45 4d 45 49 4e 44 45 20 46 52 4f 4d 20 46 55 5f 4c 5f 47 45 4d 45 49 4e 44 45 5f 4f 52 54 53 54 45 49 4c 22 } //01 00 
		$a_00_2 = {73 74 72 44 41 54 45 49 4e 65 77 20 3d 20 44 41 54 55 4d 5f 44 41 54 45 49 20 26 20 22 42 41 43 4b 55 50 2e 4d 53 50 5f 54 6f 6f 6c 2e 78 6c 73 6d 22 } //01 00 
		$a_00_3 = {73 74 72 44 41 54 45 49 4e 65 77 56 69 73 69 6f 6e 20 3d 20 44 41 54 55 4d 5f 44 41 54 45 49 20 26 20 22 6e 65 77 56 69 73 69 6f 6e 2e 4d 53 50 5f 54 6f 6f 6c 2e 78 6c 73 6d 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_182{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {52 61 6e 67 65 28 22 70 72 6f 63 65 73 73 69 6e 67 44 61 74 65 22 29 20 3d 20 53 75 62 6d 69 74 56 41 54 52 65 74 75 72 6e 41 50 49 2e 50 72 6f 63 65 73 73 69 6e 67 44 61 74 65 } //02 00 
		$a_00_1 = {2e 52 61 6e 67 65 28 22 63 68 61 72 67 65 52 65 66 4e 75 6d 62 65 72 22 29 20 3d 20 22 27 22 20 26 20 53 75 62 6d 69 74 56 41 54 52 65 74 75 72 6e 41 50 49 2e 43 68 61 72 67 65 52 65 66 4e 75 6d 62 65 72 } //02 00 
		$a_00_2 = {45 72 72 2e 52 61 69 73 65 20 2e 73 74 61 74 75 73 2c 20 22 53 75 62 6d 69 74 56 41 54 52 65 74 75 72 6e 41 50 49 22 2c 20 22 54 68 65 20 56 41 54 20 72 65 74 75 72 6e 20 77 61 73 20 61 6c 72 65 61 64 79 20 73 75 62 6d 69 74 74 65 64 20 66 6f 72 20 74 68 65 20 67 69 76 65 6e 20 70 65 72 69 6f 64 2e 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_183{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 57 6f 72 6b 73 68 65 65 74 73 28 69 29 2e 43 65 6c 6c 73 28 31 2c 20 6c 61 73 74 63 6f 6c 20 2b 20 31 29 2e 56 61 6c 75 65 20 3d 20 22 54 6f 74 61 6c 43 61 6c 63 75 6c 61 74 69 6f 6e 56 61 6c 75 65 } //02 00 
		$a_01_1 = {54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 57 6f 72 6b 73 68 65 65 74 73 28 69 29 2e 43 65 6c 6c 73 28 31 2c 20 6c 61 73 74 63 6f 6c 20 2b 20 32 29 2e 56 61 6c 75 65 20 3d 20 22 54 6f 74 61 6c 49 6e 76 6f 69 63 65 56 61 6c 75 65 } //02 00 
		$a_01_2 = {54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 57 6f 72 6b 73 68 65 65 74 73 28 69 29 2e 43 65 6c 6c 73 28 72 2c 20 6c 61 73 74 63 6f 6c 20 2b 20 31 29 2e 56 61 6c 75 65 20 3d 20 74 6f 74 61 6c 73 70 6c 69 74 75 70 76 61 6c 75 65 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_184{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 70 76 74 54 61 62 6c 65 20 3d 20 57 6f 72 6b 73 68 65 65 74 73 28 22 42 72 61 6e 64 20 53 68 65 65 74 4e 61 6d 65 4c 69 73 74 22 29 2e 52 61 6e 67 65 28 22 41 31 22 29 2e 50 69 76 6f 74 54 61 62 6c 65 } //01 00 
		$a_00_1 = {53 65 74 20 70 76 74 54 61 62 6c 65 20 3d 20 57 6f 72 6b 73 68 65 65 74 73 28 22 57 48 53 4c 20 53 68 65 65 74 4e 61 6d 65 4c 69 73 74 22 29 2e 52 61 6e 67 65 28 22 41 31 22 29 2e 50 69 76 6f 74 54 61 62 6c 65 } //01 00 
		$a_00_2 = {41 66 74 65 72 42 79 53 68 65 65 74 4e 61 6d 65 20 3d 20 22 54 6f 74 61 6c 20 53 68 65 65 74 4e 61 6d 65 4c 69 73 74 22 } //01 00 
		$a_00_3 = {50 75 62 6c 69 63 20 53 75 62 20 43 6f 70 79 44 61 74 61 28 42 79 56 61 6c 20 44 6f 6f 72 4e 61 6d 65 20 41 73 20 53 74 72 69 6e 67 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_185{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {6d 79 41 70 70 2e 57 6f 72 6b 62 6f 6f 6b 73 2e 4f 70 65 6e 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 56 42 45 2e 56 42 50 72 6f 6a 65 63 74 73 28 22 4c 73 41 67 58 4c 42 22 29 2e 46 69 6c 65 4e 61 6d 65 2c 20 46 61 6c 73 65 } //01 00 
		$a_00_1 = {49 66 20 57 62 2e 4e 61 6d 65 20 3c 3e 20 22 4c 73 41 67 58 4c 42 2e 78 6c 61 22 20 54 68 65 6e } //01 00 
		$a_00_2 = {57 6f 72 6b 62 6f 6f 6b 73 2e 4f 70 65 6e 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 57 6f 72 6b 62 6f 6f 6b 73 28 22 4c 73 41 67 58 4c 42 2e 78 6c 61 22 29 2e 50 61 74 68 20 26 20 22 5c 4c 73 41 67 58 4c 42 2e 78 6c 61 6d 22 } //01 00 
		$a_00_3 = {72 65 74 20 3d 20 49 6e 53 74 72 28 31 2c 20 6c 43 65 6c 6c 2e 46 6f 72 6d 75 6c 61 2c 20 22 4c 73 41 67 58 4c 42 2e 78 6c 61 27 21 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_186{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {74 6f 20 6f 76 65 72 72 69 64 65 20 73 65 74 20 60 4a 73 6f 6e 43 6f 6e 76 65 72 74 65 72 2e 4a 73 6f 6e 4f 70 74 69 6f 6e 73 2e 55 73 65 44 6f 75 62 6c 65 46 6f 72 4c 61 72 67 65 4e 75 6d 62 65 72 73 20 3d 20 54 72 75 65 60 } //01 00 
		$a_00_1 = {68 74 74 70 73 3a 2f 2f 67 69 74 68 75 62 2e 63 6f 6d 2f 56 42 41 2d 74 6f 6f 6c 73 2f 56 42 41 2d 55 74 63 43 6f 6e 76 65 72 74 65 72 } //01 00 
		$a_00_2 = {45 72 72 2e 52 61 69 73 65 20 31 30 30 30 31 2c 20 22 4a 53 4f 4e 43 6f 6e 76 65 72 74 65 72 22 } //01 00 
		$a_00_3 = {45 72 72 2e 52 61 69 73 65 20 31 30 30 31 34 2c 20 22 55 74 63 43 6f 6e 76 65 72 74 65 72 2e 43 6f 6e 76 65 72 74 54 6f 49 73 6f 22 2c 20 22 49 53 4f 20 38 36 30 31 20 63 6f 6e 76 65 72 73 69 6f 6e 20 65 72 72 6f 72 3a 20 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_187{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {50 6c 65 61 73 65 20 63 68 61 6e 67 65 20 74 68 65 20 6c 6f 63 61 74 69 6f 6e 20 6f 66 20 74 68 65 20 4d 61 70 70 69 6e 67 20 54 6f 6f 6c 20 70 61 63 6b 61 67 65 20 74 6f 20 61 20 64 69 72 65 63 74 6f 72 79 20 77 69 74 68 20 61 20 73 68 6f 72 74 65 72 20 70 61 74 68 2e } //01 00 
		$a_00_1 = {5a 69 70 5f 54 65 6d 70 6c 61 74 65 5f 50 61 74 68 20 3d 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 50 61 74 68 20 26 20 22 5c 4d 61 70 70 69 6e 67 54 6f 6f 6c 50 61 63 6b 61 67 65 5c 22 } //01 00 
		$a_00_2 = {5a 69 70 5f 4e 61 6d 65 20 3d 20 22 4d 61 70 70 69 6e 67 20 54 6f 6f 6c 20 50 61 63 6b 61 67 65 2e 7a 69 70 22 } //01 00 
		$a_00_3 = {49 66 20 46 55 46 5f 54 61 67 5f 43 6f 6c 20 3d 20 46 55 46 5f 54 61 67 5f 42 61 73 69 63 5f 43 6f 6c 20 54 68 65 6e } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_188{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 67 6f 4f 41 54 6f 6f 6c 73 20 41 73 20 63 6c 73 4f 41 54 6f 6f 6c 73 } //01 00 
		$a_00_1 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 67 63 41 70 70 6c 69 63 61 74 69 6f 6e 4e 61 6d 65 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 4f 41 20 54 6f 6f 6c 73 22 20 27 20 41 70 70 6c 69 63 61 74 69 6f 6e 20 6e 61 6d 65 } //01 00 
		$a_00_2 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 67 63 4f 41 43 6f 72 65 4c 69 62 46 69 6c 65 4e 61 6d 65 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 4f 41 54 6f 6f 6c 73 2e 78 6c 61 6d 22 } //01 00 
		$a_00_3 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 67 63 4f 41 53 6f 75 72 63 65 45 78 63 65 6c 52 69 62 62 6f 6e 57 6f 72 6b 62 6f 6f 6b 46 6f 6c 64 65 72 4e 61 6d 65 20 3d 20 22 4f 41 54 6f 6f 6c 73 4d 65 6e 75 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_189{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {43 61 6c 6c 20 43 6f 6d 6d 61 6e 64 42 61 72 73 28 22 42 45 78 20 44 65 73 69 67 6e 20 54 6f 6f 6c 62 6f 78 22 29 2e 44 65 6c 65 74 65 } //01 00 
		$a_00_1 = {43 61 6c 6c 20 43 6f 6d 6d 61 6e 64 42 61 72 73 28 22 42 45 78 20 41 6e 61 6c 79 73 69 73 20 54 6f 6f 6c 62 6f 78 22 29 2e 44 65 6c 65 74 65 } //01 00 
		$a_00_2 = {53 65 74 20 70 41 64 64 69 6e 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 63 6f 6d 2e 73 61 70 2e 62 69 2e 65 74 2e 61 6e 61 6c 79 7a 65 72 2e 61 64 64 69 6e 2e 42 45 78 43 6f 6e 6e 65 63 74 22 29 } //01 00 
		$a_00_3 = {53 65 74 20 47 65 74 42 45 78 20 3d 20 70 41 64 64 69 6e 2e 45 78 63 65 6c 49 6e 74 65 72 66 61 63 65 2e 57 6f 72 6b 62 6f 6f 6b 42 45 78 45 78 63 65 6c 41 70 70 6c 69 63 61 74 69 6f 6e 28 6c 4e 61 6d 65 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_190{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 74 72 20 3d 20 57 6f 72 6b 62 6f 6f 6b 73 2e 4f 70 65 6e 28 22 43 3a 5c 41 6c 6f 63 61 6c 5c 43 68 61 72 61 63 74 65 72 69 73 61 74 69 6f 6e 20 66 69 6c 65 73 5c 54 52 41 43 45 31 2e 63 73 76 22 29 } //01 00 
		$a_00_1 = {53 65 74 20 74 72 20 3d 20 57 6f 72 6b 62 6f 6f 6b 73 2e 4f 70 65 6e 28 22 43 3a 5c 41 6c 6f 63 61 6c 5c 43 68 61 72 61 63 74 65 72 69 73 61 74 69 6f 6e 20 66 69 6c 65 73 5c 54 52 41 43 45 32 2e 63 73 76 22 29 } //01 00 
		$a_00_2 = {74 72 2e 57 6f 72 6b 73 68 65 65 74 73 28 22 54 52 41 43 45 31 22 29 2e 52 61 6e 67 65 28 22 42 34 3a 42 32 30 34 22 29 2e 43 6f 70 79 } //01 00 
		$a_00_3 = {74 72 2e 57 6f 72 6b 73 68 65 65 74 73 28 22 54 52 41 43 45 32 22 29 2e 52 61 6e 67 65 28 22 42 34 3a 42 32 30 34 22 29 2e 43 6f 70 79 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_191{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {43 6f 6e 73 74 20 66 6e 61 6d 65 20 3d 20 22 63 3a 5c 4e 6f 74 42 61 63 6b 65 64 55 70 5c 77 64 70 76 73 30 39 37 2e 30 30 31 22 } //01 00 
		$a_00_1 = {50 72 69 6e 74 20 23 31 2c 20 22 73 65 6e 64 20 22 20 26 20 22 63 3a 5c 4e 6f 74 42 61 63 6b 65 64 55 70 5c 22 20 26 20 22 4f 46 46 4d 41 58 49 4e 31 2e 63 73 76 22 } //01 00 
		$a_00_2 = {64 46 54 50 20 3d 20 22 2f 75 30 31 2f 61 70 70 2f 6d 73 64 70 66 69 6e 2f 64 61 74 61 2f 70 6c 64 61 74 61 2f 6d 61 73 74 65 72 2f 22 20 27 4b 45 41 20 35 2e 33 56 20 50 72 6f 64 75 63 74 69 6f 6e } //01 00 
		$a_00_3 = {4d 73 67 42 6f 78 20 28 22 55 6e 61 62 6c 65 20 74 6f 20 72 65 63 6f 67 6e 69 73 65 20 79 6f 75 20 4b 45 41 20 75 73 65 72 20 49 44 2e 20 20 50 72 6f 63 65 73 73 20 74 65 72 6d 69 6e 61 74 65 64 2e 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_192{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 42 4c 4f 4f 4d 42 45 52 47 5f 4c 50 5f 4b 45 59 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 53 4f 46 54 57 41 52 45 5c 42 6c 6f 6f 6d 62 65 72 67 20 4c 2e 50 2e } //01 00 
		$a_00_1 = {42 6c 6f 6f 6d 62 65 72 67 55 49 2e 78 6c 61 } //01 00 
		$a_00_2 = {49 66 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 41 64 64 49 6e 73 28 69 29 2e 4e 61 6d 65 20 3d 20 22 42 6c 6f 6f 6d 62 65 72 67 55 49 50 50 54 22 20 54 68 65 6e } //01 00 
		$a_00_3 = {43 61 6c 6c 42 6c 6f 6f 6d 62 65 72 67 55 49 4d 61 63 72 6f 20 22 43 6c 65 61 72 43 6f 6d 70 6f 6e 65 6e 74 53 74 61 74 65 22 2c 20 63 68 61 72 74 43 6f 6e 74 72 6f 6c 2e 75 73 65 72 44 61 74 61 20 2b 20 67 57 6f 72 6b 62 6f 6f 6b 4e 61 6d 65 20 2b 20 67 57 6f 72 6b 73 68 65 65 74 4e 61 6d 65 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_193{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 41 74 6c 61 73 49 6d 70 6f 72 74 28 73 74 72 52 65 70 6f 72 74 54 79 70 65 20 41 73 20 53 74 72 69 6e 67 29 } //01 00 
		$a_00_1 = {46 69 6c 65 53 70 65 63 20 3d 20 22 46 42 49 53 20 54 61 63 74 69 63 61 6c 20 52 65 70 6f 72 74 22 } //01 00 
		$a_00_2 = {45 78 74 72 61 63 74 50 61 74 68 20 3d 20 22 5c 5c 70 6f 69 73 65 2e 68 6f 6d 65 6f 66 66 69 63 65 2e 6c 6f 63 61 6c 5c 64 61 74 61 5c 49 4e 44 5c 53 68 61 72 65 64 5c 54 72 61 6e 73 66 65 72 5c 41 54 4c 41 53 20 42 41 4d 5c 44 61 74 61 5c 22 } //01 00 
		$a_00_3 = {49 66 20 41 74 6c 61 73 49 6d 70 6f 72 74 28 53 68 65 65 74 32 2e 52 61 6e 67 65 28 22 56 5f 53 6e 41 5f 52 65 70 6f 72 74 54 79 70 65 22 29 2e 56 61 6c 75 65 29 20 3d 20 46 61 6c 73 65 20 54 68 65 6e } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_194{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 74 72 20 3d 20 57 6f 72 6b 62 6f 6f 6b 73 2e 4f 70 65 6e 28 22 43 3a 5c 41 6c 6f 63 61 6c 5c 43 68 61 72 61 63 74 65 72 69 73 61 74 69 6f 6e 20 66 69 6c 65 73 5c 54 52 41 43 45 31 2e 63 73 76 22 29 } //01 00 
		$a_00_1 = {77 62 2e 53 68 65 65 74 73 28 22 43 6f 6d 70 69 6c 65 64 20 44 61 74 61 22 29 2e 43 65 6c 6c 73 28 44 61 74 61 45 6e 74 72 79 2c 20 31 33 29 2e 56 61 6c 75 65 20 3d 20 42 61 6e 64 77 69 64 74 68 } //01 00 
		$a_00_2 = {74 72 2e 57 6f 72 6b 73 68 65 65 74 73 28 22 54 52 41 43 45 31 22 29 2e 52 61 6e 67 65 28 22 42 34 3a 42 32 30 34 22 29 2e 43 6f 70 79 } //01 00 
		$a_00_3 = {77 62 2e 53 68 65 65 74 73 28 22 43 6f 6d 70 69 6c 65 64 20 44 61 74 61 22 29 2e 43 65 6c 6c 73 28 44 61 74 61 45 6e 74 72 79 2c 20 31 29 2e 53 65 6c 65 63 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_195{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 41 50 50 5f 54 49 54 4c 45 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 49 52 45 53 53 20 41 64 64 2d 49 6e 22 } //01 00 
		$a_00_1 = {50 75 62 6c 69 63 20 53 75 62 20 49 72 65 73 73 41 64 64 69 6e 50 72 65 66 65 72 65 6e 63 65 73 28 29 } //01 00 
		$a_00_2 = {4d 73 67 42 6f 78 20 22 41 63 63 65 73 73 20 74 68 65 20 49 52 45 53 53 20 41 64 64 2d 49 6e 20 48 65 6c 70 20 62 79 20 6e 61 76 69 67 61 74 69 6e 67 20 74 6f 20 74 68 65 20 45 78 63 65 6c 20 49 6e 74 65 72 66 61 63 65 20 73 65 63 74 69 6f 6e 20 69 6e 20 74 68 65 20 49 52 45 53 53 20 48 65 6c 70 20 66 72 6f 6d 20 49 52 45 53 53 20 50 72 6f 2e 22 } //01 00 
		$a_00_3 = {53 65 74 20 69 72 65 73 73 20 3d 20 4e 65 77 20 44 66 73 49 72 65 73 73 2e 41 70 70 6c 69 63 61 74 69 6f 6e } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_196{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 53 75 62 20 45 75 72 6f 43 6f 6e 76 65 72 73 69 6f 6e 57 69 7a 61 72 64 28 29 } //01 00 
		$a_00_1 = {22 45 55 52 20 2d 3e 20 41 54 53 22 2c 20 22 45 55 52 20 2d 3e 20 42 45 46 22 2c 20 22 45 55 52 20 2d 3e 20 43 59 50 22 } //01 00 
		$a_00_2 = {22 45 55 52 20 2d 3e 20 4e 4c 47 22 2c 20 22 45 55 52 20 2d 3e 20 50 54 45 22 2c 20 22 45 55 52 20 2d 3e 20 53 49 54 22 2c 20 22 45 55 52 20 2d 3e 20 53 4b 4b 22 } //01 00 
		$a_00_3 = {49 66 20 6d 5f 69 54 72 69 61 6e 67 53 65 74 20 3d 20 54 72 75 65 20 54 68 65 6e 20 66 72 6d 41 64 76 61 6e 63 65 64 2e 54 72 69 61 6e 67 50 72 65 63 20 3d 20 6d 5f 69 54 72 69 61 6e 67 50 72 65 63 } //01 00 
		$a_00_4 = {6d 5f 69 53 6f 75 72 63 65 43 75 72 72 65 6e 63 79 20 3d 20 66 72 6d 2e 53 6f 75 72 63 65 43 75 72 72 65 6e 63 79 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_197{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {41 75 74 68 6f 72 20 2d 20 50 72 61 73 68 61 6e 74 20 44 65 73 68 70 61 6e 64 65 } //01 00 
		$a_00_1 = {50 72 69 76 61 74 65 20 50 72 6f 70 65 72 74 79 20 53 65 74 20 49 56 42 53 41 58 43 6f 6e 74 65 6e 74 48 61 6e 64 6c 65 72 5f 64 6f 63 75 6d 65 6e 74 4c 6f 63 61 74 6f 72 28 42 79 56 61 6c 20 52 48 53 20 41 73 20 4d 53 58 4d 4c 32 2e 49 56 42 53 41 58 4c 6f 63 61 74 6f 72 29 } //01 00 
		$a_00_2 = {50 72 69 76 61 74 65 20 46 75 6e 63 74 69 6f 6e 20 43 6f 6e 76 65 72 74 58 53 44 54 79 70 65 54 6f 56 42 41 54 79 70 65 28 73 58 53 44 54 79 70 65 20 41 73 20 53 74 72 69 6e 67 29 20 41 73 20 53 74 72 69 6e 67 } //01 00 
		$a_00_3 = {50 75 62 6c 69 63 20 50 72 6f 70 65 72 74 79 20 47 65 74 20 4d 65 73 73 61 67 65 73 28 29 20 41 73 20 42 6e 65 56 42 41 4d 65 73 73 61 67 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_198{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {72 61 6e 67 65 4e 61 6d 65 20 3d 20 22 7a 44 6c 67 4f 75 74 59 65 61 72 73 22 } //01 00 
		$a_00_1 = {63 6f 6c 4e 6f 20 3d 20 72 61 6e 67 65 28 22 7a 44 6c 67 4f 75 74 59 65 61 72 73 22 29 2e 43 6f 6c 75 6d 6e 73 28 72 61 6e 67 65 28 22 7a 44 6c 67 4f 75 74 59 65 61 72 73 22 29 2e 43 6f 6c 75 6d 6e 73 2e 43 6f 75 6e 74 29 2e 43 6f 6c 75 6d 6e 20 2b 20 31 } //01 00 
		$a_00_2 = {72 6f 77 4f 66 66 73 65 74 20 3d 20 72 61 6e 67 65 28 22 7a 44 6c 67 50 65 72 69 6f 64 73 22 29 2e 52 6f 77 73 28 31 29 2e 72 6f 77 } //01 00 
		$a_00_3 = {63 6f 6c 4e 6f 20 3d 20 72 61 6e 67 65 28 22 7a 44 6c 67 50 65 72 69 6f 64 73 22 29 2e 43 6f 6c 75 6d 6e 73 28 72 61 6e 67 65 28 22 7a 44 6c 67 50 65 72 69 6f 64 73 22 29 2e 43 6f 6c 75 6d 6e 73 2e 43 6f 75 6e 74 29 2e 43 6f 6c 75 6d 6e 20 2b 20 31 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_199{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,0e 00 0e 00 07 00 00 02 00 "
		
	strings :
		$a_00_0 = {53 48 45 45 54 4e 61 6d 65 20 3d 20 22 42 61 73 69 63 20 44 65 74 61 69 6c 73 20 4e 65 77 20 4d 65 6d 62 65 72 73 22 } //02 00 
		$a_00_1 = {53 48 45 45 54 4e 61 6d 65 20 3d 20 22 42 61 73 69 63 20 44 65 74 61 69 6c 73 20 45 78 69 73 74 69 6e 67 20 4d 65 6d 62 65 72 73 22 } //02 00 
		$a_00_2 = {53 48 45 45 54 4e 61 6d 65 20 3d 20 22 53 65 72 76 69 63 65 20 48 69 73 74 6f 72 79 20 43 72 69 62 20 53 68 65 65 74 22 } //02 00 
		$a_00_3 = {53 48 45 45 54 4e 61 6d 65 20 3d 20 22 57 50 53 20 52 61 74 65 20 48 69 73 74 6f 72 79 22 } //02 00 
		$a_00_4 = {53 48 45 45 54 4e 61 6d 65 20 3d 20 22 41 56 43 20 48 69 73 74 6f 72 79 22 } //02 00 
		$a_00_5 = {53 48 45 45 54 4e 61 6d 65 20 3d 20 22 42 65 6e 65 66 69 63 69 61 72 79 20 44 65 74 61 69 6c 73 22 } //02 00 
		$a_00_6 = {53 75 62 20 43 6f 6e 74 72 6f 6c 54 6f 74 61 6c 73 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_200{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {51 55 41 4c 49 54 59 20 4d 41 4e 41 47 45 4d 45 4e 54 5c 30 39 20 43 68 65 63 6b 20 74 68 65 20 43 68 65 63 6b 65 72 5c 70 72 6f 66 2d 6f 72 6d 61 73 20 61 6e 64 20 6f 6c 64 20 73 68 65 65 74 73 5c 43 54 43 20 44 69 73 70 75 74 65 2d 51 75 65 72 79 20 52 65 73 6f 6c 75 74 69 6f 6e 20 50 72 6f 66 6f 72 6d 61 2e 64 6f 63 78 } //02 00 
		$a_00_1 = {53 65 6e 74 4f 6e 42 65 68 61 6c 66 4f 66 4e 61 6d 65 20 3d 20 22 43 65 6e 74 72 61 6c 4f 70 65 72 61 74 69 6f 6e 73 51 40 68 6d 70 6f 2e 67 6f 76 2e 75 6b 22 } //02 00 
		$a_00_2 = {54 6f 20 3d 20 22 72 6f 78 61 6e 6e 65 2e 6d 63 63 75 65 40 68 6d 70 6f 2e 67 6f 76 2e 75 6b 3b 73 68 69 72 6c 65 79 2e 72 6f 62 69 6e 73 6f 6e 40 68 6d 70 6f 2e 67 6f 76 2e 75 6b 3b 6d 61 72 6b 2e 77 6f 6f 64 73 40 68 6d 70 6f 2e 67 6f 76 2e 75 6b 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_201{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 43 6f 6d 6d 61 6e 64 42 61 72 73 28 22 4b 52 4f 4e 45 53 22 29 2e 43 6f 6e 74 72 6f 6c 73 28 22 45 78 65 63 75 74 65 22 29 2e 44 65 6c 65 74 65 } //01 00 
		$a_00_1 = {56 69 65 77 45 78 65 20 3d 20 45 6e 76 69 72 6f 6e 28 22 65 6c 6e 72 75 6e 22 29 20 2b 20 22 5c 76 69 65 77 2e 65 78 65 20 2d 70 20 22 20 2b 20 56 6f 72 6c 61 67 65 } //01 00 
		$a_00_2 = {41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 53 61 76 65 41 73 20 46 69 6c 65 4e 61 6d 65 3a 3d 50 61 74 68 6e 61 6d 65 20 2b 20 22 5c 63 6f 70 79 6c 69 73 74 5f 73 70 73 2e 78 6c 73 22 2c 20 46 69 6c 65 46 6f 72 6d 61 74 3a 3d 78 6c 4e 6f 72 6d 61 6c } //01 00 
		$a_00_3 = {53 65 74 20 6f 42 61 72 20 3d 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 43 6f 6d 6d 61 6e 64 42 61 72 73 28 22 4b 52 4f 4e 45 53 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_202{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {4d 79 46 69 6c 65 20 3d 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 50 61 74 68 20 26 20 22 5c 41 75 74 6f 6d 61 74 65 64 4d 65 61 73 75 72 65 6d 65 6e 74 73 2e 74 78 74 22 } //01 00 
		$a_00_1 = {53 75 62 20 6d 79 63 6f 6c 6c 65 63 74 69 6f 6e 70 72 6f 63 65 64 75 72 65 28 29 } //01 00 
		$a_00_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 4f 6e 54 69 6d 65 20 4e 6f 77 20 2b 20 54 69 6d 65 56 61 6c 75 65 28 22 30 30 3a 30 30 3a 30 32 22 29 2c 20 22 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 6d 79 63 6f 6c 6c 65 63 74 69 6f 6e 70 72 6f 63 65 64 75 72 65 22 } //01 00 
		$a_00_3 = {4d 73 67 42 6f 78 20 28 22 49 6e 76 61 6c 69 64 20 46 69 6c 65 6e 61 6d 65 3a 20 20 4c 61 73 74 20 36 20 63 68 61 72 61 63 74 65 72 73 20 6f 66 20 66 69 6c 65 6e 61 6d 65 20 61 72 65 20 6e 6f 74 20 78 2e 78 6c 73 6d 21 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_203{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {77 65 62 61 64 69 53 68 65 65 74 20 3d 20 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 43 75 73 74 6f 6d 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 53 68 2e 43 6f 64 65 4e 61 6d 65 20 26 20 22 5f 57 45 42 41 44 49 22 29 } //01 00 
		$a_00_1 = {43 6f 6e 73 74 20 50 52 4f 44 55 43 54 5f 52 45 4c 45 41 53 45 5f 4c 41 42 45 4c 20 3d 20 22 31 32 2e 30 2e 30 2e 30 3a 20 46 72 69 64 61 79 20 46 65 62 75 72 61 72 79 20 31 30 2c 20 32 30 30 36 22 } //01 00 
		$a_00_2 = {62 6c 6f 63 6b 41 76 61 69 6c 20 3d 20 41 63 74 69 76 65 57 6f 72 6b 62 6f 6f 6b 2e 43 75 73 74 6f 6d 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 42 4c 4f 43 4b 22 20 26 20 62 6c 6f 63 6b 49 6e 64 65 78 29 } //01 00 
		$a_00_3 = {44 69 6d 20 6d 5f 52 69 62 62 6f 6e 20 41 73 20 49 52 69 62 62 6f 6e 55 49 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_204{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 43 6f 6d 6d 61 6e 64 54 65 78 74 20 3d 20 22 73 70 46 58 45 58 50 44 65 74 61 69 6c 46 78 54 72 61 6e 73 61 63 74 69 6f 6e 22 } //01 00 
		$a_00_1 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 47 65 74 46 58 48 65 67 64 65 73 46 72 6f 6d 44 65 61 6c 73 44 65 74 61 69 6c 28 42 79 56 61 6c 20 62 72 61 6e 63 68 49 44 20 41 73 20 4c 6f 6e 67 2c 20 42 79 56 61 6c 20 53 74 61 72 74 44 61 74 65 20 41 73 20 44 61 74 65 2c 20 42 79 56 61 6c 20 45 6e 64 44 61 74 65 20 41 73 20 44 61 74 65 29 } //01 00 
		$a_00_2 = {43 6f 6d 6d 61 6e 64 54 65 78 74 20 3d 20 22 73 70 46 58 45 58 50 47 65 74 4d 6f 6e 74 68 6c 79 52 65 73 75 6c 74 22 } //01 00 
		$a_00_3 = {5c 5c 73 74 6f 6c 74 7a 5c 4b 76 61 6e 74 5c 44 65 76 5c 48 65 6e 72 69 6b 5c 46 58 20 45 78 70 6f 5c 54 65 73 74 50 75 62 6c 69 73 68 5c } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_205{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {41 74 74 72 69 62 75 74 65 20 73 75 6d 70 61 67 65 74 62 6c 2e 56 42 5f 44 65 73 63 72 69 70 74 69 6f 6e 20 3d 20 22 4d 61 63 72 6f 20 72 65 63 6f 72 64 65 64 20 37 2f 32 32 2f 30 32 20 62 79 20 6d 75 72 74 68 61 22 } //02 00 
		$a_00_1 = {49 66 20 44 69 72 28 22 63 3a 5c 70 72 6f 67 72 61 6d 20 66 69 6c 65 73 5c 61 64 6f 62 65 5c 61 63 72 6f 62 61 74 20 36 2e 30 5c 61 63 72 6f 62 61 74 5c 61 63 72 6f 62 61 74 2e 65 78 65 22 2c 20 76 62 4e 6f 72 6d 61 6c 29 20 3d 20 22 22 20 54 68 65 6e } //02 00 
		$a_00_2 = {49 66 20 44 69 72 28 22 63 3a 5c 70 72 6f 67 72 61 6d 20 66 69 6c 65 73 5c 61 64 6f 62 65 5c 61 63 72 6f 62 61 74 20 36 2e 30 5c 50 44 46 4d 61 6b 65 72 5c 4f 66 66 69 63 65 5c 50 44 46 4d 61 6b 65 72 41 2e 64 6f 74 22 2c 20 76 62 4e 6f 72 6d 61 6c 29 20 3d 20 22 22 20 54 68 65 6e } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_206{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 50 72 69 6e 74 22 29 2e 53 68 61 70 65 73 28 22 70 69 63 5f 54 52 36 32 30 22 29 2e 56 69 73 69 62 6c 65 20 3d 20 46 61 6c 73 65 } //01 00 
		$a_00_1 = {46 69 6c 65 43 6f 6e 74 65 6e 74 73 20 3d 20 72 65 70 6c 61 63 65 28 46 69 6c 65 43 6f 6e 74 65 6e 74 73 2c 20 22 64 78 66 5f 42 65 61 72 69 6e 67 5f 44 22 2c 20 52 61 6e 67 65 28 22 76 61 6c 5f 42 65 61 72 69 6e 67 5f 44 22 29 2e 76 61 6c 75 65 29 } //01 00 
		$a_00_2 = {77 62 2e 53 68 65 65 74 73 28 22 50 72 69 6e 74 22 29 2e 52 61 6e 67 65 28 22 76 61 6c 5f 54 65 6d 70 65 72 61 74 75 72 65 43 6c 61 73 73 22 29 } //01 00 
		$a_00_3 = {52 61 6e 67 65 28 22 76 61 6c 5f 50 6f 6c 65 70 61 69 72 73 22 29 2e 76 61 6c 75 65 20 3d 20 49 74 65 6d 44 61 74 61 28 22 50 6f 6c 65 20 70 61 69 72 73 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_207{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {55 6d 67 65 62 75 6e 67 73 2e 53 54 61 62 5f 32 5f 41 20 3d 20 54 4d 61 72 6b 5f 41 6e 66 5f 41 6e 66 20 2b 20 54 72 69 6d 28 22 48 52 54 41 42 45 4c 4c 45 22 29 20 2b 20 54 4d 61 72 6b 5f 45 6e 64 65 } //01 00 
		$a_00_1 = {46 75 6e 63 74 69 6f 6e 20 62 77 45 72 73 65 74 7a 65 6e 28 73 74 72 45 69 6e 67 61 6e 67 20 41 73 20 53 74 72 69 6e 67 2c 20 73 74 72 4e 45 5a 29 20 41 73 20 53 74 72 69 6e 67 } //01 00 
		$a_00_2 = {49 66 20 44 6f 6b 31 2e 42 6f 6f 6b 6d 61 72 6b 73 2e 45 78 69 73 74 73 28 22 4d 4b 41 52 54 45 5f 54 41 42 22 29 20 3d 20 54 72 75 65 20 54 68 65 6e } //01 00 
		$a_00_3 = {46 75 6e 63 74 69 6f 6e 20 53 70 61 6c 74 65 6e 41 6e 7a 28 73 74 72 53 50 54 4d 61 72 6b 65 20 41 73 20 53 74 72 69 6e 67 2c 20 73 74 72 53 75 63 68 20 41 73 20 53 74 72 69 6e 67 29 20 41 73 20 49 6e 74 65 67 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_208{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {57 53 20 3d 20 22 4d 6f 74 6f 72 20 63 68 61 72 61 63 74 65 72 69 73 74 69 63 73 22 } //02 00 
		$a_00_1 = {50 6c 65 61 73 65 20 70 75 74 20 69 6e 20 74 68 65 20 70 61 73 73 77 6f 72 64 20 74 6f 20 67 65 74 20 74 6f 20 74 68 65 20 65 6e 67 69 6e 65 65 72 69 6e 67 20 6d 6f 64 65 2e 22 2c 20 22 50 61 73 73 77 6f 72 74 61 62 66 72 61 67 65 20 2f 20 70 61 73 73 77 6f 72 64 20 72 65 71 75 65 73 74 22 2c 20 22 2a 2a 2a 2a 2a 22 } //02 00 
		$a_00_2 = {57 6f 72 6b 73 68 65 65 74 73 28 22 41 63 74 75 61 74 6f 72 20 63 68 61 72 61 63 74 65 72 69 73 74 69 63 73 22 29 } //02 00 
		$a_00_3 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 22 4b 65 6e 6e 6c 69 6e 69 65 6e 62 65 72 65 63 68 6e 75 6e 67 22 } //02 00 
		$a_00_4 = {46 75 6e 63 74 69 6f 6e 20 4b 65 6e 6e 6c 69 6e 69 65 5f 62 65 72 65 63 68 6e 65 6e 28 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_209{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 65 78 63 65 6c 2d 6d 61 6c 69 6e 2e 63 6f 6d } //01 00 
		$a_00_1 = {68 74 74 70 73 3a 2f 2f 77 77 77 2e 65 78 63 65 6c 2d 70 72 61 74 69 71 75 65 2e 63 6f 6d 2f 66 72 2f 61 73 74 75 63 65 73 5f 76 62 61 2f 72 65 63 68 65 72 63 68 65 2d 74 61 62 6c 65 61 75 2d 61 72 72 61 79 2e 70 68 70 } //01 00 
		$a_00_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 63 6f 6d 6d 65 6e 74 63 61 6d 61 72 63 68 65 2e 6e 65 74 2f 66 6f 72 75 6d 2f 61 66 66 69 63 68 2d 33 31 34 33 32 34 31 33 2d 69 6d 70 6f 72 74 61 74 69 6f 6e 2d 64 65 2d 64 6f 6e 6e 65 65 73 2d 73 61 6e 73 2d 64 6f 75 62 6c 6f 6e 73 23 39 } //01 00 
		$a_00_3 = {68 74 74 70 3a 2f 2f 61 6b 6f 65 62 65 6c 2e 66 72 65 65 2e 66 72 2f 77 61 6e 61 64 6f 6f 2f 63 61 74 68 79 2f 76 62 61 2f 6f 62 6a 5f 78 6c 5f 67 72 61 70 68 5f 73 65 72 69 65 73 2e 68 74 6d } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_210{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 57 6f 72 6b 73 68 65 65 74 73 28 54 45 4d 50 5f 53 48 45 45 54 5f 4e 41 4d 45 5f 43 4f 56 45 52 29 2e 50 72 6f 74 65 63 74 20 50 61 73 73 77 6f 72 64 3a 3d 50 52 4f 54 45 43 54 5f 50 41 53 53 } //01 00 
		$a_00_1 = {73 50 61 74 68 20 3d 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 50 61 74 68 20 26 20 22 5c 22 20 26 20 22 57 72 69 74 65 2e 74 78 74 22 } //01 00 
		$a_00_2 = {43 61 6c 6c 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 57 6f 72 6b 73 68 65 65 74 73 28 54 45 4d 50 5f 53 48 45 45 54 5f 4e 41 4d 45 5f 53 41 54 49 53 46 59 29 2e 44 65 6c 65 74 65 53 61 74 69 73 66 79 53 6b 69 70 } //01 00 
		$a_00_3 = {49 66 20 28 43 68 65 63 6b 56 61 6c 69 64 61 74 69 6f 6e 28 6f 53 68 65 65 74 2c 20 6c 52 6f 77 2c 20 52 45 53 41 52 43 48 5f 43 4f 4c 55 4d 4e 5f 41 4e 53 57 45 52 29 29 20 54 68 65 6e } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_211{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {74 6d 70 20 3d 20 22 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 20 28 78 38 36 29 5c 44 66 6d 5c 54 45 4c 4e 2e 74 78 74 22 } //01 00 
		$a_00_1 = {49 66 20 28 45 6e 76 69 72 6f 6e 28 22 55 73 65 72 4e 61 6d 65 22 29 20 3d 20 22 50 45 30 31 38 30 30 38 35 33 22 20 4f 72 20 45 6e 76 69 72 6f 6e 28 22 55 73 65 72 4e 61 6d 65 22 29 20 3d 20 22 65 70 65 63 6f 22 29 20 54 68 65 6e } //01 00 
		$a_00_2 = {74 6d 70 20 3d 20 22 43 3a 5c 5f 6d 69 74 5c 54 6f 6f 6c 73 5c 22 20 26 20 70 72 67 4e 61 6d 65 20 26 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 50 61 74 68 53 65 70 61 72 61 74 6f 72 } //01 00 
		$a_00_3 = {76 62 43 72 69 74 69 63 61 6c 20 4f 72 20 76 62 4f 4b 4f 6e 6c 79 2c 20 22 53 6f 72 72 79 2c 20 74 68 69 73 20 41 70 70 6c 69 63 61 74 69 6f 6e 20 69 73 20 57 6f 72 6b 69 6e 67 20 4f 4e 4c 59 20 66 72 6f 6d 20 22 20 26 20 74 6d 70 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_212{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 53 6f 6c 76 65 72 50 61 74 68 20 26 20 22 21 53 6f 6c 76 65 72 4f 6b 22 2c 20 22 24 42 24 32 36 22 2c 20 32 2c 20 30 2c 20 22 24 42 24 31 35 3a 24 42 24 31 39 22 2c 20 31 2c 20 22 47 52 47 20 4e 6f 6e 6c 69 6e 65 61 72 22 } //02 00 
		$a_00_1 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 53 6f 6c 76 65 72 50 61 74 68 20 26 20 22 21 53 6f 6c 76 65 72 52 65 73 65 74 22 } //02 00 
		$a_00_2 = {52 65 63 6f 6d 6d 65 6e 64 65 64 20 73 65 74 74 69 6e 67 73 20 5b 68 74 74 70 73 3a 2f 2f 77 77 77 2e 6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d 2f 65 6e 2d 75 73 2f 6d 69 63 72 6f 73 6f 66 74 2d 33 36 35 2f 62 6c 6f 67 2f 32 30 30 39 2f 30 33 2f 31 32 2f 65 78 63 65 6c 2d 76 62 61 2d 70 65 72 66 6f 72 6d 61 6e 63 65 2d 63 6f 64 69 6e 67 2d 62 65 73 74 2d 70 72 61 63 74 69 63 65 73 2f 5d } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_213{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {4a 6f 75 72 6e 61 6c 5f 6e 61 6d 65 20 3d 20 22 55 4b 42 41 20 31 30 30 31 32 38 32 36 20 41 44 49 20 22 20 26 20 46 6f 72 6d 61 74 28 44 61 74 65 2c 20 22 44 44 4d 4d 59 59 22 29 } //01 00 
		$a_00_1 = {43 6f 6e 73 74 20 50 52 4f 44 55 43 54 5f 43 4f 44 45 5f 4c 41 42 45 4c 20 3d 20 22 38 2e 34 2e 31 2e 33 38 22 } //01 00 
		$a_00_2 = {43 6f 6e 73 74 20 50 52 4f 44 55 43 54 5f 52 45 4c 45 41 53 45 5f 4c 41 42 45 4c 20 3d 20 22 38 2e 34 2e 31 2e 33 38 20 57 65 64 6e 65 73 64 61 79 20 33 31 20 4a 61 6e 75 61 72 79 20 32 30 30 37 22 } //01 00 
		$a_00_3 = {50 75 62 6c 69 63 20 53 75 62 20 43 72 65 61 74 65 4c 61 79 6f 75 74 5f 4f 76 65 72 66 6c 6f 77 5f 32 30 30 5f 42 4e 45 5f 48 4f 46 41 53 5f 32 28 78 6c 61 70 70 20 41 73 20 41 70 70 6c 69 63 61 74 69 6f 6e 2c 20 4c 61 79 6f 75 74 53 68 65 65 74 20 41 73 20 57 6f 72 6b 73 68 65 65 74 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_214{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {57 6f 72 6b 62 6f 6f 6b 73 2e 4f 70 65 6e 20 28 22 5c 5c 62 72 75 6d 6d 65 72 2e 73 65 5c 62 66 73 5c 42 46 53 2d 4f 70 65 72 61 74 69 6f 6e 73 5c 46 75 6e 63 74 69 6f 6e 20 73 68 65 65 74 5c 64 61 74 61 5c 66 75 6e 63 74 69 6f 6e 20 73 68 65 65 74 20 73 74 61 74 69 63 2e 78 6c 73 78 22 29 } //01 00 
		$a_00_1 = {49 66 20 66 75 6e 64 20 3d 20 22 54 61 6c 61 72 69 75 6d 22 20 4f 72 20 66 75 6e 64 20 3d 20 22 46 43 43 22 20 54 68 65 6e } //01 00 
		$a_00_2 = {57 6f 72 6b 62 6f 6f 6b 73 28 22 66 75 6e 63 74 69 6f 6e 20 73 68 65 65 74 20 64 61 74 61 20 50 50 2e 78 6c 73 78 22 29 2e 43 6c 6f 73 65 20 28 46 61 6c 73 65 29 } //01 00 
		$a_00_3 = {70 61 74 68 20 3d 20 22 5c 5c 62 72 75 6d 6d 65 72 2e 73 65 5c 62 66 73 5c 42 46 53 2d 4f 70 65 72 61 74 69 6f 6e 73 5c 4d 4f 5c 46 75 6e 63 74 69 6f 6e 20 53 68 65 65 74 5c 41 72 63 68 69 76 65 5c 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_215{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 46 6f 6c 6c 6f 77 48 79 70 65 72 6c 69 6e 6b 20 41 64 64 72 65 73 73 3a 3d 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 74 65 61 63 68 65 72 73 70 65 6e 73 69 6f 6e 73 2e 63 6f 2e 75 6b 2f 6d 63 72 67 75 69 64 65 73 22 } //02 00 
		$a_00_1 = {50 72 69 76 61 74 65 20 53 75 62 20 62 74 6e 56 69 65 77 55 49 5f 53 65 63 42 5f 43 6c 69 63 6b 28 29 } //02 00 
		$a_00_2 = {69 6e 74 41 6e 73 20 3d 20 4d 73 67 42 6f 78 28 70 72 6f 6d 70 74 3a 3d 22 54 68 65 20 63 6f 6e 74 72 69 62 75 74 69 6f 6e 20 61 6d 6f 75 6e 74 73 20 77 69 6c 6c 20 62 65 20 67 65 6e 65 72 61 74 65 64 20 61 6e 64 20 76 61 6c 69 64 61 74 65 64 20 62 61 73 65 64 20 6f 6e 20 74 68 65 20 6d 65 6d 62 65 72 20 69 6e 66 6f 72 6d 61 74 69 6f 6e 20 79 6f 75 20 68 61 76 65 20 70 72 6f 76 69 64 65 64 20 69 6e 20 53 65 63 74 69 6f 6e 20 41 2e 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_216{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,09 00 09 00 06 00 00 05 00 "
		
	strings :
		$a_00_0 = {44 65 76 65 6c 6f 70 65 64 20 62 79 20 4d 69 63 68 61 65 6c 20 45 69 66 66 6c 61 65 6e 64 65 72 20 2f 20 41 45 20 53 6f 66 74 77 61 72 65 20 53 6f 6c 75 74 69 6f 6e 73 } //01 00 
		$a_00_1 = {50 75 62 6c 69 63 20 74 4d 69 6c 65 73 74 6f 6e 65 73 28 35 30 30 30 29 20 41 73 20 54 6d 69 6c 65 73 74 6f 6e 65 } //01 00 
		$a_00_2 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 61 63 62 44 6f 65 73 4f 62 6a 45 78 69 73 74 28 6f 62 6a 29 } //01 00 
		$a_00_3 = {50 75 62 6c 69 63 20 6f 62 6a 50 50 54 20 41 73 20 4f 62 6a 65 63 74 20 27 50 6f 77 65 72 50 6f 69 6e 74 2e 41 70 70 6c 69 63 61 74 69 6f 6e } //01 00 
		$a_00_4 = {46 75 6e 63 74 69 6f 6e 20 61 62 62 72 65 76 69 61 74 65 5f 4d 53 5f 4e 61 6d 65 28 6d 73 4e 61 6d 65 29 } //01 00 
		$a_00_5 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 74 72 69 6d 54 69 6d 65 28 64 61 74 65 5f 77 69 74 68 5f 74 69 6d 65 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_217{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 53 55 42 4b 45 59 20 3d 20 22 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 41 70 70 20 50 61 74 68 73 5c 49 54 47 44 6f 63 58 2e 65 78 65 22 } //01 00 
		$a_00_1 = {73 74 72 4d 73 67 20 3d 20 73 74 72 4d 73 67 20 26 20 22 2d 20 49 54 20 4e 65 74 20 44 65 73 69 67 6e 20 41 70 70 20 4e 6f 74 20 49 6e 73 74 61 6c 6c 65 64 2e 22 } //01 00 
		$a_00_2 = {53 65 74 20 76 69 73 41 64 64 4f 6e 20 3d 20 56 69 73 69 6f 2e 41 64 64 6f 6e 73 2e 41 64 64 28 73 74 72 41 70 70 50 61 74 68 20 26 20 22 49 54 47 44 6f 63 58 2e 65 78 65 22 29 } //01 00 
		$a_00_3 = {56 69 73 69 6f 2e 41 64 64 6f 6e 73 2e 49 74 65 6d 28 73 74 72 41 70 70 50 61 74 68 20 26 20 22 49 54 47 44 6f 63 58 2e 65 78 65 22 29 2e 52 75 6e 20 28 22 44 65 76 69 63 65 53 70 65 63 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_218{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {78 41 6e 6f 76 61 31 20 3d 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 28 47 65 74 4d 61 63 72 6f 52 65 67 49 64 28 22 66 6e 41 6e 6f 76 61 31 22 29 2c 20 69 6e 70 72 6e 67 2c 20 6f 75 74 72 6e 67 2c 20 67 72 6f 75 70 65 64 2c 20 6c 61 62 65 6c 73 2c 20 61 6c 70 68 61 29 } //02 00 
		$a_00_1 = {78 41 6e 6f 76 61 31 51 20 3d 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 28 47 65 74 4d 61 63 72 6f 52 65 67 49 64 28 22 66 6e 41 6e 6f 76 61 31 51 22 29 2c 20 69 6e 70 72 6e 67 2c 20 6f 75 74 72 6e 67 2c 20 67 72 6f 75 70 65 64 2c 20 6c 61 62 65 6c 73 2c 20 61 6c 70 68 61 29 } //02 00 
		$a_00_2 = {78 41 6e 6f 76 61 32 20 3d 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 28 47 65 74 4d 61 63 72 6f 52 65 67 49 64 28 22 66 6e 41 6e 6f 76 61 32 22 29 2c 20 69 6e 70 72 6e 67 2c 20 6f 75 74 72 6e 67 2c 20 73 61 6d 70 6c 65 5f 72 6f 77 73 2c 20 61 6c 70 68 61 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_219{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {49 66 20 41 63 74 69 76 65 43 65 6c 6c 2e 56 61 6c 75 65 20 3d 20 22 43 6f 6d 70 61 6e 79 20 43 6f 64 65 22 } //01 00 
		$a_00_1 = {63 6f 6c 4f 72 64 72 20 3d 20 41 72 72 61 79 28 22 44 69 76 69 73 69 6f 6e 22 2c 20 22 50 52 44 2e 48 69 65 72 35 20 44 65 73 63 22 2c 20 22 4d 61 74 65 72 69 61 6c 20 4e 6f 22 2c 20 22 4d 61 74 65 72 69 61 6c 20 44 65 73 63 72 69 70 74 69 6f 6e 22 2c 20 22 51 74 79 20 41 76 61 69 6c 61 62 6c 65 22 2c 20 22 43 6f 6d 70 61 6e 79 20 43 6f 64 65 22 2c 20 22 50 6c 61 6e 74 22 29 } //01 00 
		$a_00_2 = {53 65 74 20 77 72 20 3d 20 57 6f 72 6b 62 6f 6f 6b 73 2e 4f 70 65 6e 28 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 53 74 6f 63 6b 4c 69 73 74 22 29 2e 52 61 6e 67 65 28 22 43 37 22 29 29 } //01 00 
		$a_00_3 = {41 63 74 69 76 65 43 65 6c 6c 2e 56 61 6c 75 65 20 3d 20 22 4d 61 74 65 72 69 61 6c 20 44 65 73 63 72 69 70 74 69 6f 6e 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_220{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {6f 45 6e 76 2e 53 61 76 65 56 61 72 69 61 62 6c 65 20 22 6d 5f 4f 41 54 61 62 6c 65 4a 6f 69 6e 51 75 65 72 79 22 2c 20 6d 5f 4f 41 54 61 62 6c 65 4a 6f 69 6e 51 75 65 72 79 } //01 00 
		$a_00_1 = {6f 45 6e 76 2e 53 61 76 65 56 61 72 69 61 62 6c 65 20 22 6d 5f 4f 41 54 61 62 6c 65 4e 61 6d 65 22 2c 20 6d 5f 4f 41 54 61 62 6c 65 4e 61 6d 65 } //01 00 
		$a_00_2 = {43 61 6c 6c 20 4d 73 67 42 6f 78 28 22 4f 41 20 52 65 70 6f 72 74 73 20 63 6f 75 6c 64 20 6e 6f 74 20 66 69 6e 64 20 6e 61 6d 65 64 20 72 61 6e 67 65 20 27 22 20 26 20 73 52 61 6e 67 65 4e 61 6d 65 20 26 20 22 27 2e 22 2c 20 76 62 4f 4b 4f 6e 6c 79 20 2b 20 76 62 45 78 63 6c 61 6d 61 74 69 6f 6e 2c 20 22 4f 41 20 52 65 70 6f 72 74 73 22 29 } //01 00 
		$a_00_3 = {49 66 20 4c 65 66 74 28 2e 45 72 72 6f 72 54 69 74 6c 65 2c 20 4c 65 6e 28 22 4f 41 20 45 64 69 74 6f 72 22 29 29 20 3d 20 22 4f 41 20 45 64 69 74 6f 72 22 20 54 68 65 6e } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_221{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {50 72 69 76 61 74 65 20 43 6f 6e 73 74 20 43 44 58 4c 41 64 64 49 6e 50 72 6f 67 49 44 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 43 68 65 6d 44 72 61 77 45 78 63 65 6c 41 64 64 49 6e 31 39 2e 45 78 63 65 6c 41 64 64 49 6e 22 } //01 00 
		$a_00_1 = {43 53 42 52 2d 31 31 39 30 31 30 3a 20 52 75 6e 20 6d 65 74 68 6f 64 20 72 65 74 75 72 6e 20 6e 75 6c 6c 20 69 6e 20 63 68 65 6d 64 72 61 77 65 78 63 65 6c } //01 00 
		$a_00_2 = {43 53 42 52 2d 31 32 38 35 33 34 3a 20 53 61 76 65 64 20 77 6f 72 6b 73 68 65 65 74 20 69 73 20 6e 6f 74 20 72 65 63 6f 67 6e 69 7a 65 64 20 61 73 20 61 20 43 68 65 6d 4f 66 66 69 63 65 20 77 6f 72 6b 73 68 65 65 74 20 77 68 65 6e 20 72 65 6f 70 65 6e 20 69 74 } //01 00 
		$a_00_3 = {50 75 62 6c 69 63 20 53 75 62 20 43 53 58 4c 5f 4d 61 6b 65 4e 65 77 43 53 57 6f 72 6b 73 68 65 65 74 28 42 79 52 65 66 20 62 4d 61 64 65 53 68 65 65 74 20 41 73 20 42 6f 6f 6c 65 61 6e 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_222{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 08 00 00 01 00 "
		
	strings :
		$a_00_0 = {42 6c 6f 6f 6d 62 65 72 67 55 49 2e 78 6c 61 } //01 00 
		$a_00_1 = {42 42 50 54 5f 6d 6f 64 55 74 69 6c 69 74 79 5f 58 4c 2e 62 61 73 } //01 00 
		$a_00_2 = {62 61 74 42 6c 6f 6f 6d 62 65 72 67 41 75 74 6f 43 6f 6c 6f 72 54 79 70 65 } //01 00 
		$a_00_3 = {42 6c 6f 6f 6d 62 65 72 67 5c 4f 66 66 69 63 65 20 54 6f 6f 6c 73 5c 50 6f 77 65 72 54 6f 6f 6c 73 } //01 00 
		$a_00_4 = {67 41 64 64 69 6e 4c 6f 61 64 65 72 2e 4c 6f 61 64 4c 6f 63 61 6c 6c 79 20 22 42 6c 6f 6f 6d 62 65 72 67 55 49 50 50 54 4d 61 73 74 65 72 2e 70 70 61 22 } //01 00 
		$a_00_5 = {42 6c 6f 6f 6d 62 65 72 67 20 41 50 49 20 2d 20 54 6f 6f 6c 73 50 72 6f 78 79 } //01 00 
		$a_00_6 = {61 64 64 69 6e 50 61 74 68 20 3d 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 41 64 64 49 6e 73 28 22 42 6c 6f 6f 6d 62 65 72 67 55 49 50 50 54 22 29 2e 70 61 74 68 20 26 20 22 5c 22 20 26 20 61 64 64 69 6e 4e 61 6d 65 } //01 00 
		$a_00_7 = {42 6c 6f 6f 6d 62 65 72 67 20 50 6f 77 65 72 54 6f 6f 6c 73 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_223{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 64 72 69 76 65 72 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 65 6c 65 6e 69 75 6d 2e 45 64 67 65 44 72 69 76 65 72 22 29 } //01 00 
		$a_00_1 = {64 72 69 76 65 72 2e 47 65 74 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 74 75 74 6f 72 69 61 6c 73 70 6f 69 6e 74 2e 63 6f 6d 2f 69 6e 64 65 78 2e 68 74 6d 22 } //01 00 
		$a_00_2 = {50 72 69 76 61 74 65 20 44 72 69 76 65 72 20 41 73 20 53 65 6c 65 6e 69 75 6d 2e 45 64 67 65 44 72 69 76 65 72 } //01 00 
		$a_00_3 = {72 69 76 65 72 2e 46 69 6e 64 45 6c 65 6d 65 6e 74 42 79 49 64 28 22 44 72 6f 70 44 6f 77 6e 4c 69 73 74 4d 53 46 69 73 63 61 6c 59 65 61 72 22 29 2e 53 65 6e 64 4b 65 79 73 20 43 65 6c 6c 73 28 72 2c 20 33 29 2e 56 61 6c 75 65 } //01 00 
		$a_00_4 = {46 75 6e 63 74 69 6f 6e 20 53 70 6c 69 74 39 37 28 73 53 74 72 20 41 73 20 56 61 72 69 61 6e 74 2c 20 73 64 65 6c 69 6d 20 41 73 20 53 74 72 69 6e 67 29 20 41 73 20 56 61 72 69 61 6e 74 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_224{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {70 61 74 68 5f 64 62 20 3d 20 22 4d 3a 5c 53 69 74 65 73 5c 42 72 61 69 6e 65 5c 47 54 53 4f 5c 47 50 44 49 5c 43 43 50 44 5c 41 6e 61 6c 79 74 69 63 73 5c 44 42 20 50 51 41 5c 44 61 74 61 42 61 73 65 20 55 50 53 20 56 31 2e 30 5f 62 65 2e 61 63 63 64 62 22 } //01 00 
		$a_00_1 = {49 66 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 41 63 74 69 76 65 53 68 65 65 74 2e 42 6f 75 74 6f 6e 5f 62 72 61 69 6e 65 2e 56 61 6c 75 65 20 3d 20 54 72 75 65 20 54 68 65 6e 20 73 69 74 65 20 3d 20 22 42 52 41 5f 55 50 53 5f 54 32 22 } //01 00 
		$a_00_2 = {49 66 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 41 63 74 69 76 65 53 68 65 65 74 2e 42 6f 75 74 6f 6e 5f 73 6c 6f 75 67 68 2e 56 61 6c 75 65 20 3d 20 54 72 75 65 20 54 68 65 6e 20 73 69 74 65 20 3d 20 22 53 4c 48 5f 55 50 53 5f 41 4a 41 58 22 } //01 00 
		$a_00_3 = {53 71 6c 20 3d 20 22 53 45 4c 45 43 54 20 2a 20 46 52 4f 4d 20 30 35 5f 55 50 53 5f 43 72 65 77 20 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_225{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {49 66 20 28 53 68 74 4e 61 6d 65 20 3d 20 22 44 42 22 29 20 4f 72 20 28 53 68 74 4e 61 6d 65 20 3d 20 22 54 49 54 4c 45 22 29 20 4f 72 20 28 53 68 74 4e 61 6d 65 20 3d } //01 00 
		$a_00_1 = {4d 79 43 6c 6e 20 3d 20 72 31 2e 46 69 6e 64 28 6d 6f 6a 69 2c 20 4c 6f 6f 6b 41 74 3a 3d 78 6c 57 68 6f 6c 65 2c 20 4d 61 74 63 68 43 61 73 65 3a 3d 54 72 75 65 29 2e 43 6f 6c 75 6d 6e } //01 00 
		$a_00_2 = {43 61 6c 6c 20 57 6f 72 6b 73 68 65 65 74 5f 53 65 74 74 69 6e 67 28 73 68 74 31 2c 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 4e 61 6d 65 2c 20 44 42 73 68 74 4e 61 6d 65 29 3a 20 49 66 20 73 68 74 31 20 49 73 20 4e 6f 74 68 69 6e 67 20 54 68 65 6e 20 45 78 69 74 20 53 75 62 } //01 00 
		$a_00_3 = {44 69 6d 20 73 68 74 31 20 41 73 20 45 78 63 65 6c 2e 57 6f 72 6b 73 68 65 65 74 3a 20 53 65 74 20 73 68 74 31 20 3d 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 57 6f 72 6b 73 68 65 65 74 73 28 4f 55 54 73 68 65 65 74 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_226{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {49 46 28 43 4f 55 4e 54 41 28 5b 40 49 44 5d 3a 5b 40 5b 49 73 20 74 68 65 20 63 61 70 69 74 61 6c 20 70 72 6f 6a 65 63 74 20 77 69 74 68 69 6e 20 6f 72 20 61 62 6f 76 65 20 61 70 70 72 6f 76 65 64 20 43 50 4c 3f 5d 5d 29 3c 3d 31 } //01 00 
		$a_00_1 = {5b 40 5b 49 73 20 74 68 65 20 63 61 70 69 74 61 6c 20 70 72 6f 6a 65 63 74 20 69 6e 63 6c 75 64 65 64 20 69 6e 20 74 68 65 20 31 30 20 79 65 61 72 20 43 61 70 69 74 61 6c 20 49 6e 76 65 73 74 6d 65 6e 74 20 50 6c 61 6e 3f 20 2a 5d 5d } //01 00 
		$a_00_2 = {5b 40 5b 50 75 62 6c 69 73 68 20 45 73 74 2e 20 45 78 70 2e 20 74 6f 20 33 30 2d 4a 75 6e 20 49 6e 64 69 63 61 74 6f 72 5d 5d } //01 00 
		$a_00_3 = {5b 40 5b 45 73 74 69 6d 61 74 65 64 20 54 6f 74 61 6c 20 43 6f 73 74 20 28 24 30 30 30 29 20 2a 5d 5d } //01 00 
		$a_00_4 = {5b 40 5b 45 73 74 69 6d 61 74 65 64 20 46 69 6e 61 6e 63 69 61 6c 20 43 6f 6d 70 6c 65 74 69 6f 6e 20 4d 6f 6e 74 68 2f 59 65 61 72 20 2a 5d 5d } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_227{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_00_0 = {43 6f 6e 73 74 20 41 70 69 50 72 65 66 69 78 4d 50 52 65 6c 20 3d 20 22 68 74 74 70 73 3a 2f 2f 73 70 32 30 31 33 2e 6d 79 61 74 6f 73 2e 6e 65 74 2f 6f 72 67 2f 65 77 6c 2f 69 6e 74 70 72 6f 6a 2f 50 72 6f 6a 73 2f 4c 37 39 33 38 25 32 30 2d 25 32 30 4d 65 72 63 68 2f 5f 61 70 69 22 } //02 00 
		$a_00_1 = {6d 65 74 68 6f 64 20 3d 20 22 47 45 54 22 3a 20 71 75 65 72 79 20 3d 20 22 2f 53 50 5f 54 65 6e 61 6e 74 53 65 74 74 69 6e 67 73 5f 43 75 72 72 65 6e 74 22 } //02 00 
		$a_00_2 = {6d 65 74 68 6f 64 20 3d 20 22 47 45 54 22 3a 20 71 75 65 72 79 20 3d 20 22 2f 77 65 62 2f 47 65 74 46 6f 6c 64 65 72 42 79 53 65 72 76 65 72 52 65 6c 61 74 69 76 65 55 72 6c 28 27 2f 6f 72 67 61 6e 69 7a 61 74 69 6f 6e 2f 67 62 75 2f 46 77 6c 2f 65 77 6c 2f 63 6f 6f 2f 50 61 79 6d 65 6e 74 73 20 70 72 6f 64 75 63 74 73 2f 49 50 50 20 47 6f 76 65 72 6e 61 6e 63 65 2f 43 52 2d 50 52 4f 4a 45 43 54 53 2f 32 30 32 31 27 29 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_228{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 53 50 4d 53 58 44 61 74 61 46 69 6c 65 4e 61 6d 65 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 46 4f 44 4d 63 6f 6d 6d 4d 53 58 44 61 74 61 2e 78 6c 73 78 22 } //01 00 
		$a_00_1 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 6d 79 43 4f 53 4d 49 43 6d 61 69 6e 55 52 4c 53 74 72 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 68 74 74 70 73 3a 2f 2f 63 6f 73 6d 69 63 2e 63 72 6d 2e 64 79 6e 61 6d 69 63 73 2e 63 6f 6d 22 } //01 00 
		$a_00_2 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 6d 79 4d 53 58 6d 61 69 6e 55 52 4c 53 74 72 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 68 74 74 70 73 3a 2f 2f 6d 69 63 72 6f 73 6f 66 74 73 61 6c 65 73 2e 63 72 6d 2e 64 79 6e 61 6d 69 63 73 2e 63 6f 6d 22 } //01 00 
		$a_00_3 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 6e 65 77 42 65 74 61 57 62 4e 61 6d 65 20 41 73 20 53 74 72 69 6e 67 20 3d 20 54 6f 6f 6c 4e 61 6d 65 20 26 20 22 28 62 65 74 61 29 2e 78 6c 73 6d } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_229{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {4d 73 67 42 6f 78 20 22 50 6c 65 61 73 65 20 70 6f 70 75 6c 61 74 65 20 43 44 45 53 20 4d 61 74 63 68 20 54 79 70 65 20 63 6f 6c 75 6d 6e 20 61 73 20 70 65 72 20 73 65 6c 65 63 74 69 6f 6e 20 6f 6e 20 53 74 61 72 74 20 48 65 72 65 20 74 61 62 2e 20 50 6c 65 61 73 65 20 63 68 65 63 6b 20 77 69 74 68 20 47 53 47 2f 53 4f 50 20 66 6f 72 20 61 6e 79 20 63 6c 61 72 69 66 69 63 61 74 69 6f 6e 22 } //01 00 
		$a_00_1 = {53 68 65 65 74 73 28 22 46 59 31 37 4c 61 6e 67 6c 6f 63 22 29 2e 56 69 73 69 62 6c 65 20 3d 20 69 } //01 00 
		$a_00_2 = {4c 6f 63 61 6c 5f 4e 75 72 74 75 72 65 20 3d 20 53 68 65 65 74 73 28 22 4d 61 72 6b 65 74 6f 20 4c 4d 22 29 2e 52 61 6e 67 65 28 22 43 33 31 22 29 2e 56 61 6c 75 65 } //01 00 
		$a_00_3 = {49 66 20 53 68 65 65 74 73 28 22 44 61 74 61 62 61 73 65 5f 44 61 74 61 22 29 2e 43 65 6c 6c 73 28 31 2c 20 69 29 2e 56 61 6c 75 65 20 3d 20 22 4c 65 61 64 4d 61 74 63 68 53 6f 75 72 63 65 4e 61 6d 65 22 20 54 68 65 6e } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_230{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 06 00 00 02 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 46 4f 72 69 20 3d 20 43 65 6c 44 65 4e 6f 6d 42 61 73 65 28 22 43 65 6c 52 65 66 54 4d 50 22 29 } //02 00 
		$a_00_1 = {4e 6f 6d 46 75 6c 6c 4f 72 69 20 3d 20 46 4f 72 69 2e 50 61 72 65 6e 74 2e 4e 61 6d 65 } //02 00 
		$a_00_2 = {53 65 74 20 62 20 3d 20 46 4f 72 69 2e 52 61 6e 67 65 28 46 4f 72 69 2e 43 65 6c 6c 73 28 50 72 69 46 69 6c 20 2d 20 31 2c 20 50 72 69 43 6f 6c 29 2c 20 46 4f 72 69 2e 43 65 6c 6c 73 28 50 72 69 46 69 6c 20 2d 20 31 2c 20 55 6c 74 43 6f 6c 29 29 } //02 00 
		$a_00_3 = {53 65 74 20 46 44 65 73 20 3d 20 43 65 6c 44 65 4e 6f 6d 42 61 73 65 28 22 43 65 6c 52 65 66 52 65 73 22 29 } //02 00 
		$a_00_4 = {46 44 65 73 2e 50 61 72 65 6e 74 2e 43 65 6c 6c 73 2e 43 6c 65 61 72 43 6f 6e 74 65 6e 74 73 } //02 00 
		$a_00_5 = {53 65 74 20 62 20 3d 20 46 44 65 73 2e 52 61 6e 67 65 28 46 44 65 73 2e 43 65 6c 6c 73 28 50 72 69 46 69 6c 2c 20 50 72 69 43 6f 6c 29 2c 20 46 44 65 73 2e 43 65 6c 6c 73 28 55 6c 74 46 69 6c 2c 20 55 6c 74 43 6f 6c 29 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_231{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {43 30 31 20 2d 20 53 70 65 63 69 66 79 20 74 68 65 20 66 69 6e 61 6e 63 69 61 6c 20 69 6e 73 74 69 74 75 74 69 6f 6e 20 61 73 20 69 74 20 73 68 6f 75 6c 64 20 61 70 70 65 61 72 20 6f 6e 20 74 68 65 20 53 4d 53 20 52 65 70 6f 72 74 73 } //01 00 
		$a_00_1 = {43 31 33 20 2d 20 46 49 4e 41 4e 43 49 41 4c 20 54 52 41 4e 53 41 43 54 49 4f 4e 20 46 45 45 20 43 4f 4c 4c 45 43 54 49 4f 4e 20 2f 20 46 55 4e 44 53 20 44 49 53 42 55 52 53 45 4d 45 4e 54 } //01 00 
		$a_00_2 = {43 32 30 20 2d 20 56 45 52 53 49 4f 4e 20 32 2e 33 20 46 49 4e 41 4e 43 49 41 4c 20 54 52 41 4e 53 41 43 54 49 4f 4e 20 2f 20 46 45 45 20 52 45 43 4f 52 44 } //01 00 
		$a_00_3 = {43 30 36 20 2d 20 41 43 51 55 49 52 45 52 20 41 44 4a 55 53 54 4d 45 4e 54 20 26 20 4d 45 52 43 48 41 4e 44 49 53 45 20 43 52 45 44 20 44 45 54 41 49 4c } //01 00 
		$a_00_4 = {43 31 37 20 2d 20 41 44 4d 49 4e 49 53 54 52 41 54 49 56 45 20 4d 45 53 53 41 47 45 20 31 20 54 52 41 4e 53 41 43 54 49 4f 4e 20 52 45 43 4f 52 44 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_232{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {61 75 74 45 43 4c 50 53 2e 53 65 6e 64 4b 65 79 73 20 22 56 53 52 49 4e 49 56 41 53 41 22 20 26 20 22 6c 65 61 73 65 70 6c 61 6e 31 22 } //01 00 
		$a_00_1 = {53 75 62 20 53 65 74 45 6e 76 44 65 74 61 69 6c 73 28 45 6e 76 4e 61 6d 65 20 41 73 20 53 74 72 69 6e 67 2c 20 70 77 64 20 41 73 20 53 74 72 69 6e 67 2c 20 4f 70 74 69 6f 6e 61 6c 20 75 73 72 4e 61 6d 65 20 41 73 20 53 74 72 69 6e 67 20 3d 20 22 56 53 52 49 4e 49 56 41 53 41 22 29 } //01 00 
		$a_00_2 = {4e 6f 6c 73 45 6d 75 6c 61 74 6f 72 20 3d 20 22 58 3a 5c 55 73 65 72 73 5c 73 72 69 6e 65 5c 44 65 73 6b 74 6f 70 5c 50 43 35 32 35 30 20 45 6d 75 6c 61 74 6f 72 20 69 63 6f 6e 2d 22 20 26 20 45 6e 76 4e 6f 20 26 20 22 2d 62 6f 78 2e 57 53 22 } //01 00 
		$a_00_3 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 4c 61 75 6e 63 68 50 43 4f 4d 4d 53 65 73 73 69 6f 6e 28 50 72 6f 66 69 6c 65 4e 61 6d 65 20 41 73 20 53 74 72 69 6e 67 2c 20 53 65 73 73 69 6f 6e 49 44 20 41 73 20 49 6e 74 65 67 65 72 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_233{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {67 73 74 72 4c 6f 63 61 6c 44 6f 63 50 61 74 68 20 3d 20 73 74 72 44 6f 77 6e 6c 6f 61 64 50 61 74 68 20 26 20 22 44 41 54 41 54 45 4c 22 20 26 20 73 74 72 4c 6f 63 61 6c 44 6f 63 45 78 74 65 6e 73 69 6f 6e } //01 00 
		$a_00_1 = {67 73 74 72 4c 6f 63 61 6c 44 61 74 61 50 61 74 68 20 3d 20 73 74 72 44 6f 77 6e 6c 6f 61 64 50 61 74 68 20 26 20 22 44 41 54 41 54 45 4c 2e 54 58 54 22 } //01 00 
		$a_00_2 = {6d 65 74 68 6f 64 20 77 68 65 6e 20 74 68 65 20 64 6f 63 75 6d 65 6e 74 20 69 73 20 61 6c 72 65 61 64 79 20 73 61 76 65 64 20 69 73 20 74 68 61 74 20 69 74 20 6d 61 79 20 70 72 6f 64 75 63 65 20 61 6e 20 65 78 74 72 61 20 22 53 45 4c 45 43 54 20 46 52 4f 4d 20 44 41 54 41 54 45 4c 2e 54 58 54 22 } //01 00 
		$a_00_3 = {49 20 68 61 76 65 20 70 61 73 74 65 64 20 74 68 65 20 63 6f 64 65 20 77 68 69 63 68 20 6d 6f 64 69 66 69 65 64 20 74 68 65 20 4f 44 43 20 74 6f 20 72 65 66 65 72 65 6e 63 65 20 74 68 65 20 64 6f 77 6e 6c 6f 61 64 65 64 20 44 41 54 41 54 45 4c 2e 54 58 54 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_234{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 73 75 63 68 65 28 44 61 74 65 6e 62 6c 61 74 74 20 41 73 20 53 74 72 69 6e 67 2c 20 53 70 61 6c 74 65 20 41 73 20 53 74 72 69 6e 67 29 } //01 00 
		$a_00_1 = {44 69 6d 20 4d 65 72 6b 6d 61 6c 63 6f 6c 75 6d 6e 20 41 73 20 49 6e 74 65 67 65 72 2c 20 42 65 6d 65 72 6b 75 6e 67 31 63 6f 6c 75 6d 6e 20 41 73 20 49 6e 74 65 67 65 72 2c 20 42 65 6d 65 72 6b 75 6e 67 32 63 6f 6c 75 6d 6e 20 41 73 20 49 6e 74 65 67 65 72 2c 20 50 61 72 61 6d 65 74 65 72 72 6f 77 20 41 73 20 49 6e 74 65 67 65 72 } //01 00 
		$a_00_2 = {49 66 20 76 61 72 69 61 62 6c 65 20 3d 20 22 43 46 32 5f 37 30 5f 5a 55 42 45 48 4f 45 52 5f 43 4f 4e 54 49 46 4f 52 4d 22 20 54 68 65 6e } //01 00 
		$a_00_3 = {50 75 62 6c 69 63 20 45 6e 64 77 65 72 74 31 31 6b 6f 6d 6d 69 73 73 69 6f 6e 20 41 73 20 49 6e 74 65 67 65 72 2c 20 45 6e 64 77 65 72 74 31 32 6b 6f 6d 6d 69 73 73 69 6f 6e 20 41 73 20 49 6e 74 65 67 65 72 2c 20 45 6e 64 77 65 72 74 31 33 6b 6f 6d 6d 69 73 73 69 6f 6e 20 41 73 20 49 6e 74 65 67 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_235{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {57 6f 72 6b 62 6f 6f 6b 73 2e 4f 70 65 6e 20 28 22 5c 5c 62 72 75 6d 6d 65 72 2e 73 65 5c 62 66 73 5c 42 46 53 2d 4f 70 65 72 61 74 69 6f 6e 73 5c 46 75 6e 63 74 69 6f 6e 20 73 68 65 65 74 5c 64 61 74 61 5c 66 75 6e 63 74 69 6f 6e 20 73 68 65 65 74 20 73 74 61 74 69 63 2e 78 6c 73 78 22 29 } //01 00 
		$a_00_1 = {57 6f 72 6b 62 6f 6f 6b 73 28 22 66 75 6e 63 74 69 6f 6e 20 73 68 65 65 74 20 73 74 61 74 69 63 2e 78 6c 73 78 22 29 2e 43 6c 6f 73 65 20 28 46 61 6c 73 65 } //01 00 
		$a_00_2 = {70 61 74 68 20 3d 20 22 5c 5c 62 72 75 6d 6d 65 72 2e 73 65 5c 62 66 73 5c 42 46 53 2d 4f 70 65 72 61 74 69 6f 6e 73 5c 4d 4f 5c 46 75 6e 63 74 69 6f 6e 20 53 68 65 65 74 5c 41 72 63 68 69 76 65 22 } //01 00 
		$a_00_3 = {57 6f 72 6b 62 6f 6f 6b 73 2e 4f 70 65 6e 20 28 22 5c 5c 62 72 75 6d 6d 65 72 2e 73 65 5c 62 66 73 5c 42 46 53 2d 4f 70 65 72 61 74 69 6f 6e 73 5c 66 75 6e 63 74 69 6f 6e 20 73 68 65 65 74 5c 64 61 74 61 5c 66 75 6e 63 74 69 6f 6e 20 73 68 65 65 74 20 64 61 74 61 20 50 50 2e 78 6c 73 78 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_236{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,0d 00 0d 00 05 00 00 0a 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 53 75 62 20 47 65 74 4f 53 45 41 70 70 6c 69 63 61 74 69 6f 6e 28 42 79 52 65 66 20 72 65 74 76 61 6c 20 41 73 20 41 73 70 65 6e 4f 53 45 57 6f 72 6b 62 6f 6f 6b 2e 4f 53 45 41 70 70 6c 69 63 61 74 69 6f 6e 29 } //0a 00 
		$a_00_1 = {50 75 62 6c 69 63 20 53 75 62 20 47 65 74 41 53 57 41 70 70 6c 69 63 61 74 69 6f 6e 28 42 79 52 65 66 20 72 65 74 76 61 6c 20 41 73 20 41 73 70 65 6e 4f 53 45 57 6f 72 6b 62 6f 6f 6b 2e 4f 53 45 41 70 70 6c 69 63 61 74 69 6f 6e 29 } //01 00 
		$a_00_2 = {61 70 70 2e 45 78 65 63 75 74 65 43 6f 6d 6d 61 6e 64 20 28 22 41 73 70 65 6e 54 65 63 68 2e 41 53 57 58 4c 2e 43 6f 6d 6d 61 6e 64 73 2e 52 75 6e 43 6f 6d 6d 61 6e 64 22 29 } //01 00 
		$a_00_3 = {61 70 70 2e 45 78 65 63 75 74 65 43 6f 6d 6d 61 6e 64 20 28 22 41 73 70 65 6e 54 65 63 68 2e 41 53 57 58 4c 2e 43 6f 6d 6d 61 6e 64 73 2e 45 78 63 65 6c 32 4d 6f 64 65 6c 43 6f 6d 6d 61 6e 64 22 29 } //01 00 
		$a_00_4 = {61 70 70 2e 45 78 65 63 75 74 65 43 6f 6d 6d 61 6e 64 20 28 22 41 73 70 65 6e 54 65 63 68 2e 41 53 57 58 4c 2e 43 6f 6d 6d 61 6e 64 73 2e 4c 6f 61 64 53 6e 61 70 73 68 6f 74 43 6f 6d 6d 61 6e 64 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_237{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 63 61 6c 63 75 6c 61 74 65 4e 65 77 47 72 6f 73 73 41 76 61 69 6c 61 62 69 6c 69 74 79 28 75 6e 61 76 61 69 6c 61 62 69 6c 69 74 79 44 69 63 74 69 6f 6e 61 72 79 20 41 73 20 44 69 63 74 69 6f 6e 61 72 79 2c 20 62 69 6e 6f 63 73 41 76 61 69 6c 61 62 69 6c 69 74 79 4d 6e 67 20 41 73 20 42 69 6e 6f 63 73 41 76 61 69 6c 61 62 69 6c 69 74 79 4d 61 6e 61 67 65 72 29 20 41 73 20 44 69 63 74 69 6f 6e 61 72 79 } //01 00 
		$a_00_1 = {50 72 69 76 61 74 65 20 70 41 70 69 4d 61 6e 61 67 65 72 20 41 73 20 41 70 69 44 61 74 61 4d 61 6e 61 67 65 72 } //01 00 
		$a_00_2 = {50 72 69 76 61 74 65 20 46 75 6e 63 74 69 6f 6e 20 63 72 65 61 74 65 43 68 75 6e 6b 54 61 62 6c 65 52 65 6d 6f 76 65 44 61 74 65 73 41 6e 64 51 75 61 6e 74 69 74 79 46 6f 72 45 78 70 65 72 74 69 73 65 28 42 79 52 65 66 20 64 65 6d 61 6e 64 54 61 62 6c 65 20 41 73 20 54 61 62 6c 65 29 20 41 73 20 54 61 62 6c 65 } //01 00 
		$a_00_3 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 67 65 74 45 6d 70 6c 6f 79 65 65 57 6f 72 6b 52 65 67 69 6d 65 28 65 6d 70 6c 6f 79 65 65 43 6f 64 65 20 41 73 20 53 74 72 69 6e 67 29 20 41 73 20 44 6f 75 62 6c 65 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_238{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {4d 73 67 42 6f 78 20 28 22 56 45 48 49 43 4c 45 20 2f 20 54 52 41 49 4c 45 52 20 43 4f 55 4c 44 20 4e 4f 54 20 42 45 20 46 4f 55 4e 44 2e 20 50 4c 45 41 53 45 20 53 45 41 52 43 48 20 41 47 41 49 4e 2c 20 4f 52 20 45 4e 54 45 52 20 44 45 54 41 49 4c 53 20 4d 41 4e 55 41 4c 4c 59 2e 22 29 2c 20 76 62 45 78 63 6c 61 6d 61 74 69 6f 6e 2c 20 22 50 4c 45 41 53 45 20 4e 4f 54 45 21 22 } //01 00 
		$a_00_1 = {54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 53 68 65 65 74 73 28 22 4f 43 54 20 28 46 29 22 29 2e 53 65 6c 65 63 74 } //01 00 
		$a_00_2 = {49 66 20 53 68 69 70 2e 76 61 6c 75 65 20 3d 20 22 4d 53 4d 22 20 4f 72 20 53 68 69 70 2e 76 61 6c 75 65 20 3d 20 22 4e 4f 52 4d 41 4e 44 49 45 22 20 54 68 65 6e } //01 00 
		$a_00_3 = {50 4c 45 41 53 45 20 43 4f 4d 50 4c 45 54 45 20 41 4c 4c 20 4d 41 4e 44 41 54 4f 52 59 20 42 4f 58 45 53 20 42 45 46 4f 52 45 20 43 4f 4e 54 49 4e 55 49 4e 47 2e 20 49 46 20 52 45 43 4f 52 44 49 4e 47 20 41 20 48 55 42 20 53 45 4c 45 43 54 49 4f 4e 2c 20 4d 41 4b 45 20 53 55 52 45 20 54 4f 20 43 4f 4e 44 55 43 54 20 41 20 53 45 41 52 43 48 20 46 4f 52 20 54 48 45 20 56 45 48 49 43 4c 45 20 2f 20 54 52 41 49 4c 45 52 20 52 45 47 20 46 49 52 53 54 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_239{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {61 73 73 65 6d 62 6c 61 2e 63 6f 6d 2f 73 70 61 63 65 73 2f 73 6b 61 62 65 6c 6f 6e 64 65 73 69 67 6e 2d 70 72 6f 64 75 63 74 69 6f 6e 74 65 61 6d 2f 77 69 6b 69 2f 47 65 6e 76 65 6a 73 74 61 73 74 65 72 5f 69 5f 57 6f 72 64 45 6e 67 69 6e 65 } //01 00 
		$a_00_1 = {43 61 73 65 20 22 62 74 6e 57 61 76 65 31 22 2c 20 22 62 74 6e 57 61 76 65 32 22 2c 20 22 62 74 6e 57 61 76 65 33 22 2c 20 22 62 74 6e 57 61 76 65 34 22 2c 20 22 62 74 6e 57 61 76 65 35 22 2c 20 22 62 74 6e 50 69 63 74 75 72 65 53 6d 61 6c 6c 22 2c 20 22 62 74 6e 42 6f 74 74 6f 6d 42 6f 72 64 65 72 53 68 6f 77 22 2c 20 22 62 74 6e 42 6f 74 74 6f 6d 42 6f 72 64 65 72 48 69 64 65 22 } //01 00 
		$a_00_2 = {4a 41 53 20 32 33 2f 31 31 2d 32 30 31 32 20 44 69 73 61 62 6c 65 64 20 61 6e 64 20 62 43 68 65 63 6b 42 6f 78 56 61 6c 75 65 20 72 65 74 75 72 6e 20 70 61 72 61 6d 65 74 65 72 20 61 64 64 65 64 } //01 00 
		$a_00_3 = {64 62 67 4e 6f 43 68 65 63 6b 70 6f 69 6e 74 73 20 3d 20 64 62 67 4c 6f 67 45 72 72 6f 72 20 4f 72 20 64 62 67 4c 6f 67 57 61 72 6e 69 6e 67 20 4f 72 20 64 62 67 4c 6f 67 49 6e 66 6f 72 6d 61 74 69 6f 6e 61 6c 20 4f 72 20 64 62 67 57 69 6e 64 6f 77 50 72 6f 63 20 4f 72 20 64 62 67 52 65 73 6f 75 72 63 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_240{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 65 74 20 45 6e 74 72 79 53 68 65 65 74 20 3d 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 57 6f 72 6b 73 68 65 65 74 73 28 22 56 65 72 73 69 6f 6e 22 29 } //01 00 
		$a_00_1 = {70 72 65 66 69 78 20 3d 20 22 49 4e 53 45 52 54 20 49 4e 54 4f 20 72 65 66 64 61 74 61 76 61 6c 75 65 68 69 65 72 61 72 63 68 79 20 28 70 61 72 65 6e 74 49 64 2c 20 63 68 69 6c 64 49 64 29 20 56 41 4c 55 45 53 22 } //01 00 
		$a_00_2 = {50 72 6f 64 75 63 65 48 65 61 64 65 72 20 66 69 6c 65 6e 61 6d 65 2c 20 22 45 78 74 65 72 6e 61 6c 53 79 73 74 65 6d 20 72 65 66 65 72 65 6e 63 65 20 64 61 74 61 20 73 63 72 69 70 74 22 2c 20 72 65 6c 65 61 73 65 } //01 00 
		$a_00_3 = {70 72 65 66 69 78 20 3d 20 22 49 4e 53 45 52 54 20 49 4e 54 4f 20 52 65 66 44 61 74 61 53 65 74 20 28 52 65 66 44 61 74 61 53 65 74 49 64 2c 20 52 65 66 44 61 74 61 53 65 74 4e 61 6d 65 2c 20 52 65 66 44 61 74 61 53 65 74 44 65 73 63 2c 20 53 68 6f 72 74 44 65 73 63 4c 65 6e 67 74 68 2c 20 49 6e 69 74 69 61 6c 44 61 74 61 46 69 6c 65 4e 61 6d 65 2c 20 43 72 65 61 74 65 64 55 73 65 72 49 64 2c 20 43 72 65 61 74 65 64 44 61 74 65 54 69 6d 65 2c 20 4c 61 73 74 55 70 64 61 74 65 64 55 73 65 72 49 64 2c 20 4c 61 73 74 55 70 64 61 74 65 64 44 61 74 65 54 69 6d 65 29 20 56 41 4c 55 45 53 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_241{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 43 72 65 61 74 65 4e 65 77 44 6f 6f 72 28 42 79 56 61 6c 20 44 6f 6f 72 4e 61 6d 65 20 41 73 20 53 74 72 69 6e 67 2c 20 42 79 56 61 6c 20 50 43 5f 63 6f 64 65 20 41 73 20 53 74 72 69 6e 67 2c 20 42 79 56 61 6c 20 53 74 6f 72 65 4e 61 6d 65 20 41 73 20 53 74 72 69 6e 67 2c 20 42 79 56 61 6c 20 41 66 74 65 72 42 79 53 68 65 65 74 4e 61 6d 65 20 41 73 20 53 74 72 69 6e 67 } //01 00 
		$a_00_1 = {53 75 62 20 4d 6f 76 65 41 66 74 65 72 28 42 79 56 61 6c 20 44 6f 6f 72 4e 61 6d 65 20 41 73 20 53 74 72 69 6e 67 2c 20 42 79 56 61 6c 20 41 66 74 65 72 42 79 53 68 65 65 74 4e 61 6d 65 20 41 73 20 53 74 72 69 6e 67 29 } //01 00 
		$a_00_2 = {61 72 72 20 3d 20 41 72 72 61 79 28 22 41 72 63 27 54 65 72 79 78 22 2c 20 22 41 74 6f 6d 69 63 22 2c 20 22 50 50 22 2c 20 22 50 72 65 63 6f 72 22 2c 20 22 53 61 6c 48 47 22 2c 20 22 53 61 6c 6f 6d 6f 6e 22 2c 20 22 53 75 75 6e 74 6f 22 2c 20 22 57 69 6c 73 6f 6e 20 47 6f 6c 66 22 2c 20 22 57 69 6c 73 6f 6e 20 52 61 63 6b 65 74 22 2c 20 22 57 69 6c 73 6f 6e 20 53 47 22 2c 20 22 57 69 6c 73 6f 6e 20 54 45 41 4d 22 29 } //01 00 
		$a_00_3 = {43 61 6c 6c 20 72 65 67 69 6f 6e 43 6f 70 79 44 61 74 61 28 44 6f 6f 72 4e 61 6d 65 2c 20 22 45 31 36 22 2c 20 22 51 31 32 34 22 2c 20 22 45 31 33 22 2c 20 22 51 31 32 31 22 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_242{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {53 75 62 20 55 70 64 61 74 65 54 65 61 6d 4f 6e 54 65 61 6d 48 61 70 70 69 6e 65 73 73 53 68 65 65 74 28 73 68 20 41 73 20 45 78 63 65 6c 2e 57 6f 72 6b 73 68 65 65 74 2c 20 6c 6e 67 53 70 72 69 6e 74 4e 72 20 41 73 20 4c 6f 6e 67 2c 20 4f 70 74 69 6f 6e 61 6c 20 62 54 72 61 6e 73 66 65 72 20 41 73 20 42 6f 6f 6c 65 61 6e 20 3d 20 46 61 6c 73 65 29 } //01 00 
		$a_00_1 = {50 72 69 76 61 74 65 20 53 75 62 20 56 65 72 77 69 6a 64 65 72 52 65 67 65 6c 55 69 74 53 70 72 69 6e 74 50 6c 61 6e 6e 69 6e 67 53 68 65 65 74 28 73 68 20 41 73 20 45 78 63 65 6c 2e 57 6f 72 6b 73 68 65 65 74 2c 20 69 52 6f 77 45 6d 70 6c 6f 79 65 65 20 41 73 20 4c 6f 6e 67 29 } //01 00 
		$a_00_2 = {46 75 6e 63 74 69 6f 6e 20 43 6f 75 6e 74 53 70 72 69 6e 74 50 6c 61 6e 6e 69 6e 67 53 68 65 65 74 73 28 4f 70 74 69 6f 6e 61 6c 20 62 45 78 69 73 74 73 20 41 73 20 42 6f 6f 6c 65 61 6e 20 3d 20 54 72 75 65 29 20 41 73 20 4c 6f 6e 67 } //01 00 
		$a_00_3 = {44 69 6d 20 50 72 65 73 65 6e 74 5f 68 6f 75 72 73 2c 20 41 76 61 69 6c 61 62 69 6c 69 74 79 2c 20 41 76 61 69 6c 61 62 6c 65 5f 68 6f 75 72 73 2c 20 50 72 6f 64 75 63 74 69 76 69 74 79 2c 20 50 6c 61 6e 6e 61 62 6c 65 5f 68 6f 75 72 73 2c 20 53 50 50 48 2c 20 50 6c 61 6e 6e 61 62 6c 65 5f 73 74 6f 72 79 70 6f 69 6e 74 73 20 41 73 20 44 6f 75 62 6c 65 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_243{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 74 72 53 6f 75 72 63 65 46 69 6c 65 20 3d 20 22 5c 5c 70 6f 69 73 65 2e 68 6f 6d 65 6f 66 66 69 63 65 2e 6c 6f 63 61 6c 5c 44 61 74 61 5c 49 4e 44 5c 53 68 61 72 65 64 5c 54 72 61 6e 73 66 65 72 5c 41 41 20 44 65 76 5c 42 4e 4f 5c 4c 41 4c 5f 53 65 61 72 63 68 5f 42 45 2e 78 6c 73 78 22 } //01 00 
		$a_00_1 = {4d 73 67 42 6f 78 20 22 4e 6f 20 72 65 73 75 6c 74 73 20 66 6f 75 6e 64 2e 20 50 6c 65 61 73 65 20 63 68 65 63 6b 20 79 6f 75 72 20 63 72 69 74 65 72 69 61 20 61 6e 64 20 74 72 79 20 61 67 61 69 6e 2e 22 2c 20 76 62 49 6e 66 6f 72 6d 61 74 69 6f 6e 2c 20 22 4c 41 4c 20 53 65 61 72 63 68 20 54 6f 6f 6c 22 } //01 00 
		$a_00_2 = {4d 73 67 42 6f 78 20 22 52 65 73 75 6c 74 73 20 63 6f 6e 74 61 69 6e 20 6d 6f 72 65 20 74 68 61 6e 20 32 35 30 30 20 72 65 63 6f 72 64 73 2e 20 50 6c 65 61 73 65 20 72 65 66 69 6e 65 20 79 6f 75 72 20 73 65 61 72 63 68 20 63 72 69 74 65 72 69 61 20 61 6e 64 20 74 72 79 20 61 67 61 69 6e 2e 22 2c 20 76 62 43 72 69 74 69 63 61 6c 2c 20 22 4c 41 4c 20 53 65 61 72 63 68 20 54 6f 6f 6c 22 } //01 00 
		$a_00_3 = {73 74 72 50 61 74 68 20 3d 20 22 5c 5c 70 6f 69 73 65 2e 68 6f 6d 65 6f 66 66 69 63 65 2e 6c 6f 63 61 6c 5c 44 61 74 61 5c 49 4e 44 5c 53 68 61 72 65 64 5c 54 72 61 6e 73 66 65 72 5c 41 41 20 44 65 76 5c 42 4e 4f 5c 53 65 61 72 63 68 5f 41 75 64 69 74 5f 42 45 2e 61 63 63 64 62 22 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_244{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 08 00 00 03 00 "
		
	strings :
		$a_00_0 = {74 68 69 73 20 6d 6f 64 75 6c 65 20 73 65 6e 64 73 20 61 20 6a 71 6c 20 71 75 65 72 79 20 74 6f 20 6a 69 72 61 20 75 73 69 6e 67 20 74 68 65 20 72 65 73 74 20 61 70 69 20 61 6e 64 20 74 68 65 6e 20 70 72 6f 63 65 73 73 65 73 20 74 68 65 20 6a 73 6f 6e 20 72 65 73 70 6f 6e 73 65 } //03 00 
		$a_00_1 = {75 70 64 61 74 69 6e 67 20 74 68 65 20 72 6f 77 73 20 61 6e 64 20 63 6f 6c 75 6d 6e 73 20 69 6e 20 74 68 65 20 6a 69 72 61 20 65 78 74 72 61 63 74 20 74 61 62 6c 65 20 77 69 74 68 20 74 68 65 20 64 61 74 61 20 74 68 61 74 20 69 73 20 72 65 74 75 72 6e 65 64 } //03 00 
		$a_00_2 = {62 79 20 63 2e 20 72 6f 73 73 20 6d 63 6b 65 6e 72 69 63 6b 20 28 6d 63 6b 65 6e 63 72 40 63 6f 6e 73 75 6c 74 61 6e 74 65 6d 61 69 6c 2e 63 6f 6d 2c 20 72 6d 63 6b 65 6e 72 69 63 6b 40 73 61 70 69 65 6e 74 2e 63 6f 6d 29 } //03 00 
		$a_00_3 = {70 72 69 6f 72 20 74 6f 20 64 69 73 70 6c 61 79 69 6e 67 20 74 68 65 20 66 6f 72 6d 2c 20 70 6f 73 69 74 69 6f 6e 20 69 74 20 69 6e 20 74 68 65 20 6d 69 64 64 6c 65 20 6f 66 20 74 68 65 20 6a 69 72 61 20 65 78 74 72 61 63 74 20 73 68 65 65 74 20 77 69 6e 64 6f 77 } //02 00 
		$a_00_4 = {72 65 66 72 65 73 68 6a 69 72 61 65 78 74 72 61 63 74 } //02 00 
		$a_00_5 = {6a 69 72 61 63 72 65 64 65 6e 74 69 61 6c 73 66 6f 72 6d } //02 00 
		$a_00_6 = {61 75 74 68 65 6e 74 69 63 61 74 69 6f 6e 20 65 72 72 6f 72 20 6c 6f 67 67 69 6e 67 20 6f 6e 20 74 6f 20 6a 69 72 61 } //02 00 
		$a_00_7 = {61 75 74 68 6f 72 69 7a 61 74 69 6f 6e 20 65 72 72 6f 72 20 6c 6f 67 67 69 6e 67 20 6f 6e 20 74 6f 20 6a 69 72 61 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_245{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 18 00 00 02 00 "
		
	strings :
		$a_00_0 = {6f 72 61 63 6c 65 20 68 79 70 65 72 69 6f 6e 20 73 6d 61 72 74 20 76 69 65 77 20 66 6f 72 20 6f 66 66 69 63 65 } //02 00 
		$a_00_1 = {73 6d 61 72 74 76 69 65 77 5c 62 69 6e 5c 68 73 74 62 61 72 2e 78 6c 61 } //01 00 
		$a_00_2 = {68 73 74 62 61 72 73 6d 61 72 74 76 69 65 77 70 61 6e 65 6c } //01 00 
		$a_00_3 = {68 73 74 62 61 72 61 63 74 69 6f 6e } //01 00 
		$a_00_4 = {68 73 74 62 61 72 7a 6f 6f 6d 69 6e } //01 00 
		$a_00_5 = {68 73 74 62 61 72 7a 6f 6f 6d 6f 75 74 } //01 00 
		$a_00_6 = {68 73 74 62 61 72 70 69 76 6f 74 } //01 00 
		$a_00_7 = {68 73 74 62 61 72 6b 65 65 70 6f 6e 6c 79 } //01 00 
		$a_00_8 = {68 73 74 62 61 72 72 65 6d 6f 76 65 6f 6e 6c 79 } //01 00 
		$a_00_9 = {68 73 74 62 61 72 72 65 66 72 65 73 68 } //01 00 
		$a_00_10 = {68 73 74 62 61 72 73 75 62 6d 69 74 64 61 74 61 } //01 00 
		$a_00_11 = {68 73 74 62 61 72 75 6e 64 6f } //01 00 
		$a_00_12 = {68 73 74 62 61 72 72 65 64 6f } //01 00 
		$a_00_13 = {68 73 74 62 61 72 63 6f 70 79 64 61 74 61 70 6f 69 6e 74 73 } //01 00 
		$a_00_14 = {68 73 74 62 61 72 70 61 73 74 65 64 61 74 61 70 6f 69 6e 74 73 } //01 00 
		$a_00_15 = {68 73 74 62 61 72 62 69 65 64 69 74 } //01 00 
		$a_00_16 = {68 73 74 62 61 72 70 6f 76 6d 61 6e 61 67 65 72 } //01 00 
		$a_00_17 = {68 73 74 62 61 72 6d 65 6d 62 65 72 73 65 6c 65 63 74 69 6f 6e } //01 00 
		$a_00_18 = {68 73 74 62 61 72 66 75 6e 63 74 69 6f 6e 62 75 69 6c 64 65 72 } //01 00 
		$a_00_19 = {68 73 74 62 61 72 61 64 6a 75 73 74 } //01 00 
		$a_00_20 = {68 73 74 62 61 72 63 65 6c 6c 63 6f 6d 6d 65 6e 74 73 } //01 00 
		$a_00_21 = {68 73 74 62 61 72 73 75 70 70 6f 72 74 69 6e 67 64 65 74 61 69 6c 73 } //01 00 
		$a_00_22 = {68 73 74 62 61 72 74 61 6b 65 6f 66 66 6c 69 6e 65 } //01 00 
		$a_00_23 = {68 73 74 62 61 72 72 65 66 72 65 73 68 6f 66 66 6c 69 6e 65 64 65 66 69 6e 69 74 69 6f 6e } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_246{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {49 66 20 4c 73 74 41 63 74 73 50 69 63 6b 65 64 2e 4c 69 73 74 28 6c 69 73 74 5f 69 74 65 6d 29 20 3d 20 22 2a 2a 49 4e 41 50 50 52 4f 50 52 49 41 54 45 20 43 41 4c 4c 2a 2a 22 20 54 68 65 6e } //01 00 
		$a_00_1 = {4d 73 67 42 6f 78 20 22 59 6f 75 20 6d 75 73 74 20 73 65 6c 65 63 74 20 27 33 3a 57 68 61 74 20 69 73 20 74 68 65 20 6d 61 69 6e 20 41 43 54 49 4f 4e 20 74 79 70 65 3f 27 22 } //01 00 
		$a_00_2 = {4d 73 67 42 6f 78 20 22 59 6f 75 20 6d 75 73 74 20 73 65 6c 65 63 74 20 27 37 3a 44 6f 20 79 6f 75 20 6e 65 65 64 20 74 6f 20 46 4f 52 57 41 52 44 20 6f 72 20 72 65 66 65 72 20 74 68 69 73 20 72 65 71 75 65 73 74 20 6f 6e 77 61 72 64 73 3f 27 22 } //01 00 
		$a_00_3 = {77 73 5f 6f 75 74 2e 43 65 6c 6c 73 28 77 72 69 74 65 5f 72 6f 77 2c 20 35 29 2e 56 61 6c 75 65 20 3d 20 49 49 66 28 52 61 64 42 72 61 6e 63 68 59 65 73 2c 20 22 50 72 6f 63 65 73 73 69 6e 67 22 2c 20 28 49 49 66 28 52 61 64 42 72 61 6e 63 68 4e 6f 2c 20 22 51 75 65 72 79 22 2c 20 28 49 49 66 28 52 61 64 42 72 61 6e 63 68 4f 74 68 65 72 2c 20 22 43 68 65 63 6b 22 2c 20 28 49 49 66 28 52 61 64 42 72 61 6e 63 68 4f 74 68 65 72 31 2c 20 22 42 61 69 6c 20 45 6e 64 22 2c 20 22 4f 74 68 65 72 22 29 29 29 29 29 29 29 } //01 00 
		$a_00_4 = {49 49 66 28 52 61 64 46 69 72 73 74 59 65 73 2c 20 22 43 72 6f 77 6e 20 43 6f 75 72 74 22 2c 20 28 49 49 66 28 52 61 64 46 69 72 73 74 4e 6f 2c 20 22 4d 61 67 69 73 74 72 61 74 65 73 2f 59 6f 75 74 68 22 2c 20 28 49 49 66 28 52 61 64 46 69 72 73 74 4f 74 68 65 72 2c 20 22 50 72 69 73 6f 6e 22 2c 20 28 49 49 66 28 52 61 64 46 69 72 73 74 4f 74 68 65 72 31 2c 20 22 45 4d 53 20 49 6e 74 65 72 6e 61 6c 22 2c 20 28 49 49 66 28 52 61 64 46 69 72 73 74 4f 74 68 65 72 32 2c 20 22 55 4b 42 41 22 2c 20 22 4f 74 68 65 72 22 29 29 29 29 29 29 29 29 29 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_247{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 0b 00 00 02 00 "
		
	strings :
		$a_00_0 = {71 76 69 64 69 61 6e 2e 78 6c 61 6d } //02 00 
		$a_00_1 = {69 66 20 73 61 76 69 6e 67 20 61 20 71 76 69 64 69 61 6e 20 66 69 6c 65 2c 20 75 70 64 61 74 65 20 74 68 65 20 75 69 } //02 00 
		$a_00_2 = {6c 65 61 76 69 6e 67 20 65 61 72 6c 79 20 28 71 76 69 64 69 61 6e 2e 78 6c 61 20 6f 72 20 65 6d 62 65 64 64 65 64 29 } //02 00 
		$a_00_3 = {61 72 65 20 79 6f 75 20 73 75 72 65 20 79 6f 75 20 77 69 73 68 20 74 6f 20 63 61 6e 63 65 6c 20 77 69 74 68 6f 75 74 20 73 61 76 69 6e 67 20 63 68 61 6e 67 65 73 20 62 61 63 6b 20 74 6f 20 71 76 69 64 69 61 6e 3f } //02 00 
		$a_00_4 = {73 61 76 65 20 73 70 72 65 61 64 73 68 65 65 74 20 62 61 63 6b 20 74 6f 20 74 68 65 20 71 76 69 64 69 61 6e 20 64 6f 63 75 6d 65 6e 74 } //02 00 
		$a_00_5 = {70 6c 65 61 73 65 20 70 61 73 74 65 20 79 6f 75 72 20 63 6f 6e 74 65 6e 74 20 68 65 72 65 2c 20 74 68 65 6e 20 63 6c 69 63 6b 20 27 73 61 76 65 20 74 6f 20 71 76 69 64 69 61 6e 27 } //02 00 
		$a_00_6 = {71 76 69 64 69 61 6e 73 65 72 76 65 72 20 76 61 72 69 61 62 6c 65 20 75 73 65 64 20 66 6f 72 20 6d 61 6e 61 67 69 6e 67 20 73 65 72 76 65 72 20 73 70 65 63 69 66 69 63 20 75 73 65 72 20 63 72 65 64 65 6e 74 69 61 6c 73 } //02 00 
		$a_00_7 = {70 6c 65 61 73 65 20 64 6f 77 6e 6c 6f 61 64 20 74 68 65 20 63 6f 72 72 65 63 74 20 61 64 64 2d 69 6e 73 20 62 65 66 6f 72 65 20 70 65 72 66 6f 72 6d 69 6e 67 20 61 6e 79 20 71 76 69 64 69 61 6e 20 6f 70 65 72 61 74 69 6f 6e 73 } //01 00 
		$a_00_8 = {77 6f 72 6b 20 6f 75 74 20 69 66 20 74 68 65 20 66 69 6c 65 20 69 73 20 22 6f 6e 65 20 6f 66 20 6f 75 72 73 22 20 69 6e 20 74 65 72 6d 73 20 6f 66 20 6d 75 6c 74 69 2d 65 64 69 74 } //01 00 
		$a_00_9 = {74 68 69 73 20 6c 69 74 74 6c 65 20 6e 61 73 74 79 20 68 61 63 6b 20 69 73 20 62 65 63 61 75 73 65 20 65 78 63 65 6c 20 69 73 20 66 69 72 69 6e 67 20 74 68 69 73 20 65 76 65 6e 74 20 77 69 74 68 20 61 20 62 61 64 20 77 6f 72 6b 62 6f 6f 6b } //01 00 
		$a_00_10 = {74 68 65 20 6f 6e 6c 79 20 77 61 79 20 69 20 73 65 65 6d 20 74 6f 20 62 65 20 61 62 6c 65 20 74 6f 20 74 72 61 70 20 69 74 20 69 73 20 61 63 63 65 73 73 20 74 68 65 20 6e 61 6d 65 } //00 00 
	condition:
		any of ($a_*)
 
}
rule _#ASRWin32ApiMacroExclusion_248{
	meta:
		description = "!#ASRWin32ApiMacroExclusion,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_00_0 = {46 69 6c 65 43 6f 70 79 20 6d 6f 62 6a 49 6e 66 6f 2e 50 61 74 68 47 6b 67 4d 79 50 61 72 6d 46 6f 6c 64 65 72 20 26 20 22 45 47 41 31 43 30 30 53 2e 78 6c 73 22 2c 20 6d 6f 62 6a 49 6e 66 6f 2e 50 61 74 68 4d 79 46 6f 6c 64 65 72 20 26 20 22 45 47 41 31 43 30 30 53 2e 78 6c 73 22 } //01 00 
		$a_00_1 = {46 69 6c 65 43 6f 70 79 20 6d 6f 62 6a 49 6e 66 6f 2e 50 61 74 68 47 6b 67 4d 79 50 61 72 6d 46 6f 6c 64 65 72 20 26 20 22 45 47 41 31 43 31 30 53 2e 78 6c 73 22 2c 20 6d 6f 62 6a 49 6e 66 6f 2e 50 61 74 68 4d 79 46 6f 6c 64 65 72 20 26 20 22 45 47 41 31 43 31 30 53 2e 78 6c 73 22 } //01 00 
		$a_00_2 = {46 69 6c 65 43 6f 70 79 20 6d 6f 62 6a 49 6e 66 6f 2e 50 61 74 68 47 6b 67 4d 79 50 61 72 6d 46 6f 6c 64 65 72 20 26 20 22 45 47 41 31 43 32 30 53 2e 78 6c 73 22 2c 20 6d 6f 62 6a 49 6e 66 6f 2e 50 61 74 68 4d 79 46 6f 6c 64 65 72 20 26 20 22 45 47 41 31 43 32 30 53 2e 78 6c 73 22 } //01 00 
		$a_00_3 = {46 69 6c 65 43 6f 70 79 20 6d 6f 62 6a 49 6e 66 6f 2e 50 61 74 68 47 6b 67 4d 79 50 61 72 6d 46 6f 6c 64 65 72 20 26 20 22 45 47 41 31 43 33 30 53 2e 78 6c 73 22 2c 20 6d 6f 62 6a 49 6e 66 6f 2e 50 61 74 68 4d 79 46 6f 6c 64 65 72 20 26 20 22 45 47 41 31 43 33 30 53 2e 78 6c 73 22 } //01 00 
		$a_00_4 = {46 69 6c 65 43 6f 70 79 20 6d 6f 62 6a 49 6e 66 6f 2e 50 61 74 68 47 6b 67 4d 79 50 61 72 6d 46 6f 6c 64 65 72 20 26 20 22 45 47 41 31 43 34 31 53 2e 78 6c 73 22 2c 20 6d 6f 62 6a 49 6e 66 6f 2e 50 61 74 68 4d 79 46 6f 6c 64 65 72 20 26 20 22 45 47 41 31 43 34 31 53 2e 78 6c 73 22 } //01 00 
		$a_00_5 = {46 69 6c 65 43 6f 70 79 20 6d 6f 62 6a 49 6e 66 6f 2e 50 61 74 68 47 6b 67 4d 79 50 61 72 6d 46 6f 6c 64 65 72 20 26 20 22 45 47 41 31 43 34 32 53 2e 78 6c 73 22 2c 20 6d 6f 62 6a 49 6e 66 6f 2e 50 61 74 68 4d 79 46 6f 6c 64 65 72 20 26 20 22 45 47 41 31 43 34 32 53 2e 78 6c 73 22 } //01 00 
		$a_00_6 = {46 69 6c 65 43 6f 70 79 20 6d 6f 62 6a 49 6e 66 6f 2e 50 61 74 68 47 6b 67 4d 79 50 61 72 6d 46 6f 6c 64 65 72 20 26 20 22 45 47 41 31 43 34 33 53 2e 78 6c 73 22 2c 20 6d 6f 62 6a 49 6e 66 6f 2e 50 61 74 68 4d 79 46 6f 6c 64 65 72 20 26 20 22 45 47 41 31 43 34 33 53 2e 78 6c 73 22 } //01 00 
		$a_00_7 = {46 69 6c 65 43 6f 70 79 20 6d 6f 62 6a 49 6e 66 6f 2e 50 61 74 68 47 6b 67 4d 79 50 61 72 6d 46 6f 6c 64 65 72 20 26 20 22 45 47 41 31 43 34 34 53 2e 78 6c 73 22 2c 20 6d 6f 62 6a 49 6e 66 6f 2e 50 61 74 68 4d 79 46 6f 6c 64 65 72 20 26 20 22 45 47 41 31 43 34 34 53 2e 78 6c 73 22 } //00 00 
	condition:
		any of ($a_*)
 
}