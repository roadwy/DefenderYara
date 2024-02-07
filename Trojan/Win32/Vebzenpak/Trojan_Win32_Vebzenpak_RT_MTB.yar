
rule Trojan_Win32_Vebzenpak_RT_MTB{
	meta:
		description = "Trojan:Win32/Vebzenpak.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {4e 45 79 6e 77 44 67 74 4d 74 61 47 43 4c 35 50 44 42 65 45 46 62 42 70 31 77 4b 4e 45 73 47 35 52 57 36 34 31 } //01 00  NEynwDgtMtaGCL5PDBeEFbBp1wKNEsG5RW641
		$a_81_1 = {67 65 6e 61 6e 76 65 6e 64 65 6c 73 65 73 70 72 6f 63 65 73 73 65 72 6e 65 73 } //01 00  genanvendelsesprocessernes
		$a_81_2 = {42 52 45 44 42 41 41 4e 44 53 48 4a 54 54 41 4c 45 52 } //01 00  BREDBAANDSHJTTALER
		$a_81_3 = {53 65 74 41 72 63 44 69 72 65 63 74 69 6f 6e } //01 00  SetArcDirection
		$a_81_4 = {47 65 74 4c 6f 67 69 63 61 6c 44 72 69 76 65 53 74 72 69 6e 67 73 41 } //01 00  GetLogicalDriveStringsA
		$a_81_5 = {49 73 53 79 73 74 65 6d 52 65 73 75 6d 65 41 75 74 6f 6d 61 74 69 63 } //00 00  IsSystemResumeAutomatic
	condition:
		any of ($a_*)
 
}