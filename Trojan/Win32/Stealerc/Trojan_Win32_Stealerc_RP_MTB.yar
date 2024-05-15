
rule Trojan_Win32_Stealerc_RP_MTB{
	meta:
		description = "Trojan:Win32/Stealerc.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 c0 3d cb d9 0b 00 75 06 81 c1 90 01 02 00 00 40 3d 3d a6 15 00 7c eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Stealerc_RP_MTB_2{
	meta:
		description = "Trojan:Win32/Stealerc.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 8c 38 4b 13 01 00 a1 90 01 04 88 0c 38 8b 0d 90 01 04 81 f9 90 01 01 04 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Stealerc_RP_MTB_3{
	meta:
		description = "Trojan:Win32/Stealerc.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {00 00 01 44 24 10 8b 54 24 10 8a 04 32 8b 0d 90 01 04 88 04 31 81 3d 90 01 06 00 00 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Stealerc_RP_MTB_4{
	meta:
		description = "Trojan:Win32/Stealerc.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {57 57 ff 15 7c a0 41 00 ff 15 14 a0 41 00 57 ff 15 a4 a0 41 00 81 fe 90 01 03 00 7f 09 46 81 fe 90 01 03 00 7c da 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Stealerc_RP_MTB_5{
	meta:
		description = "Trojan:Win32/Stealerc.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 44 24 08 ba 61 2a 07 c7 44 24 20 9c 16 00 48 c7 44 24 10 4d 4f 3f 0a c7 44 24 18 da 50 d8 1b c7 44 24 0c ca b6 35 54 c7 44 24 24 65 58 8c 69 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Stealerc_RP_MTB_6{
	meta:
		description = "Trojan:Win32/Stealerc.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {ba 61 2a 07 90 02 04 9c 16 00 48 90 02 04 4d 4f 3f 0a 90 02 04 da 50 d8 1b 90 02 04 ca b6 35 54 90 02 04 65 58 8c 69 90 02 04 52 8b 07 25 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Stealerc_RP_MTB_7{
	meta:
		description = "Trojan:Win32/Stealerc.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {78 61 6a 69 70 69 78 75 6b 75 6a 75 6a 65 76 6f 6d 69 72 61 67 69 76 69 6c 75 70 } //01 00  xajipixukujujevomiragivilup
		$a_01_1 = {73 6f 74 61 78 6f 6e 6f 76 69 67 61 7a 6f } //01 00  sotaxonovigazo
		$a_01_2 = {58 69 79 75 66 } //01 00  Xiyuf
		$a_01_3 = {62 65 73 6f 68 61 6b 65 78 75 78 61 6b } //00 00  besohakexuxak
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Stealerc_RP_MTB_8{
	meta:
		description = "Trojan:Win32/Stealerc.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 44 24 0c ba 61 2a 07 c7 44 24 24 9c 16 00 48 c7 44 24 14 4d 4f 3f 0a c7 44 24 1c da 50 d8 1b c7 44 24 10 ca b6 35 54 c7 44 24 28 65 58 8c 69 c7 44 24 5c 52 8b 07 25 c7 44 24 58 50 b5 81 09 c7 44 24 34 8e 34 a6 6e c7 44 24 30 52 f3 6c 10 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Stealerc_RP_MTB_9{
	meta:
		description = "Trojan:Win32/Stealerc.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 67 61 73 79 75 64 67 75 79 67 69 75 78 48 49 41 } //01 00  DgasyudguygiuxHIA
		$a_01_1 = {58 63 50 55 43 58 6c 58 6b 52 6e 79 41 64 51 } //01 00  XcPUCXlXkRnyAdQ
		$a_01_2 = {5a 74 72 62 6f 62 44 66 52 56 44 56 53 59 4a 44 62 69 54 6a 4a 59 4d 74 6e 41 70 6d 7a 6e 5a 49 49 47 6d } //01 00  ZtrbobDfRVDVSYJDbiTjJYMtnApmznZIIGm
		$a_01_3 = {64 59 75 56 58 7a 6b 4c 4c 56 57 62 63 78 70 4e 6b 7a 77 4d 51 4e 79 63 77 46 72 4d 53 68 7a 4a 44 64 77 } //00 00  dYuVXzkLLVWbcxpNkzwMQNycwFrMShzJDdw
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Stealerc_RP_MTB_10{
	meta:
		description = "Trojan:Win32/Stealerc.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 00 69 00 63 00 6f 00 70 00 20 00 72 00 75 00 68 00 69 00 20 00 6b 00 69 00 74 00 65 00 47 00 4a 00 6f 00 74 00 6f 00 73 00 75 00 6b 00 61 00 6d 00 75 00 68 00 69 00 } //01 00  Sicop ruhi kiteGJotosukamuhi
		$a_01_1 = {6f 00 73 00 6f 00 6a 00 69 00 67 00 6f 00 77 00 61 00 6d 00 20 00 6c 00 61 00 76 00 6f 00 73 00 75 00 7a 00 69 00 67 00 61 00 20 00 74 00 69 00 6e 00 6f 00 6c 00 69 00 68 00 61 00 68 00 75 00 72 00 6f 00 } //01 00  osojigowam lavosuziga tinolihahuro
		$a_01_2 = {76 00 69 00 67 00 69 00 76 00 65 00 6d 00 69 00 79 00 69 00 79 00 69 00 63 00 39 00 46 00 69 00 77 00 61 00 63 00 69 00 78 00 69 00 20 00 78 00 65 00 67 00 69 00 7a 00 65 00 7a 00 69 00 62 00 65 00 6e 00 65 00 6b 00 69 00 } //01 00  vigivemiyiyic9Fiwacixi xegizezibeneki
		$a_01_3 = {46 00 65 00 79 00 69 00 78 00 61 00 66 00 75 00 66 00 61 00 62 00 20 00 64 00 6f 00 7a 00 61 00 6d 00 65 00 63 00 65 00 79 00 6f 00 77 00 61 00 6e 00 75 00 20 00 64 00 69 00 67 00 20 00 67 00 6f 00 67 00 61 00 70 00 69 00 77 00 65 00 6b 00 20 00 6c 00 69 00 77 00 69 00 62 00 75 00 6d 00 65 00 77 00 61 00 62 00 75 00 79 00 61 00 } //01 00  Feyixafufab dozameceyowanu dig gogapiwek liwibumewabuya
		$a_01_4 = {4a 00 75 00 7a 00 61 00 6a 00 69 00 6d 00 6f 00 73 00 6f 00 79 00 65 00 7a 00 6f 00 } //01 00  Juzajimosoyezo
		$a_01_5 = {66 00 61 00 6b 00 6f 00 68 00 61 00 68 00 75 00 6b 00 6f 00 6a 00 6f 00 62 00 65 00 62 00 69 00 7a 00 69 00 66 00 6f 00 67 00 75 00 66 00 65 00 66 00 75 00 66 00 69 00 72 00 } //00 00  fakohahukojobebizifogufefufir
	condition:
		any of ($a_*)
 
}