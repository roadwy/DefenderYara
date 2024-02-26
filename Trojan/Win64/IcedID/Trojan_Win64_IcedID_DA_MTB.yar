
rule Trojan_Win64_IcedID_DA_MTB{
	meta:
		description = "Trojan:Win64/IcedID.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {42 8a 0c 2a 88 0a 48 ff c2 83 c0 90 01 01 75 90 00 } //01 00 
		$a_03_1 = {8b c2 ff c2 83 e0 90 01 01 42 8a 44 20 90 01 01 30 01 48 ff c1 3b d3 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_DA_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 03 00 00 0a 00 "
		
	strings :
		$a_00_0 = {41 8b c2 49 8b d2 48 33 d1 83 e0 3f 8a c8 48 d3 ca 48 3b d7 0f 84 5b 01 } //03 00 
		$a_81_1 = {61 67 76 79 6a 64 7a 79 70 6f 62 6e 73 61 72 67 73 } //03 00  agvyjdzypobnsargs
		$a_81_2 = {61 71 78 77 61 78 6e 79 } //00 00  aqxwaxny
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_DA_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {41 8b d0 c1 ea 10 2b c1 2b 83 90 01 04 05 c3 e6 0b 00 89 83 90 01 04 2b 4b 50 01 4b 30 48 63 4b 7c 48 8b 83 90 01 04 88 14 01 41 8b d0 44 01 53 7c 48 63 4b 7c 48 8b 83 90 01 04 c1 ea 08 88 14 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_DA_MTB_4{
	meta:
		description = "Trojan:Win64/IcedID.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 06 00 00 0a 00 "
		
	strings :
		$a_00_0 = {8b 45 04 03 45 00 69 c0 ab aa aa aa 05 aa aa aa 2a 3d 55 55 55 55 72 54 } //03 00 
		$a_80_1 = {6b 65 70 74 79 75 } //keptyu  03 00 
		$a_80_2 = {6f 72 74 70 77 } //ortpw  03 00 
		$a_80_3 = {73 6f 72 74 79 57 } //sortyW  03 00 
		$a_80_4 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //DllRegisterServer  03 00 
		$a_80_5 = {50 6c 75 67 69 6e 49 6e 69 74 } //PluginInit  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_DA_MTB_5{
	meta:
		description = "Trojan:Win64/IcedID.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4e 62 68 61 73 6a 79 66 75 61 73 68 66 6a 6b 6a 61 73 68 66 } //01 00  Nbhasjyfuashfjkjashf
		$a_01_1 = {53 63 72 69 70 74 46 72 65 65 43 61 63 68 65 } //01 00  ScriptFreeCache
		$a_01_2 = {53 63 72 69 70 74 53 75 62 73 74 69 74 75 74 65 53 69 6e 67 6c 65 47 6c 79 70 68 } //01 00  ScriptSubstituteSingleGlyph
		$a_01_3 = {49 43 44 65 63 6f 6d 70 72 65 73 73 } //01 00  ICDecompress
		$a_01_4 = {47 59 71 6c 53 74 2e 64 6c 6c } //00 00  GYqlSt.dll
	condition:
		any of ($a_*)
 
}
rule Trojan_Win64_IcedID_DA_MTB_6{
	meta:
		description = "Trojan:Win64/IcedID.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 0b 00 00 0a 00 "
		
	strings :
		$a_81_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_81_1 = {77 76 65 61 75 65 72 70 76 7a 2e 64 6c 6c } //01 00  wveauerpvz.dll
		$a_81_2 = {62 63 74 72 63 63 74 6b 75 73 63 78 6b } //01 00  bctrcctkuscxk
		$a_81_3 = {63 63 66 75 79 63 64 62 77 7a 65 76 68 77 6f } //01 00  ccfuycdbwzevhwo
		$a_81_4 = {68 73 6c 73 73 6f 6c 7a 71 61 62 79 78 61 6f 73 64 } //01 00  hslssolzqabyxaosd
		$a_81_5 = {69 7a 6d 6e 79 65 6e 65 6b 75 74 79 6e 63 73 66 71 } //01 00  izmnyenekutyncsfq
		$a_81_6 = {7a 65 67 6e 79 69 76 75 77 6a 70 2e 64 6c 6c } //01 00  zegnyivuwjp.dll
		$a_81_7 = {61 64 7a 75 69 6f 6f 70 6c 6f 6c 64 6c 76 75 62 64 } //01 00  adzuiooploldlvubd
		$a_81_8 = {62 61 78 6a 6c 65 6d 79 69 6b 75 6c 70 71 6c } //01 00  baxjlemyikulpql
		$a_81_9 = {62 6a 66 70 6c 72 61 75 65 68 77 61 6f 6e 61 6f } //01 00  bjfplrauehwaonao
		$a_81_10 = {64 68 6f 6d 6f 73 75 64 72 75 78 7a 63 68 6b } //00 00  dhomosudruxzchk
	condition:
		any of ($a_*)
 
}