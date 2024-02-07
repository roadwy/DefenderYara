
rule TrojanSpy_Win32_Nivdort_DR{
	meta:
		description = "TrojanSpy:Win32/Nivdort.DR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 44 24 18 3b 44 24 1c 0f 90 02 20 8b 44 24 14 0f b6 00 8b 4c 24 18 0f b6 11 31 c2 88 d3 88 19 90 00 } //01 00 
		$a_01_1 = {c7 41 08 06 00 00 00 c7 41 04 01 00 00 00 c7 01 02 00 00 00 ff d0 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_Nivdort_DR_2{
	meta:
		description = "TrojanSpy:Win32/Nivdort.DR,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {2f 69 6e 64 65 78 2e 70 68 70 3f 69 73 5f 70 32 70 65 6e 76 3d 5a 47 46 75 5a 32 56 73 62 79 35 68 63 32 56 75 59 32 6c 76 51 47 6b 74 62 6d 56 30 63 47 56 79 64 53 35 6a 62 32 30 75 63 47 55 4a } //01 00  /index.php?is_p2penv=ZGFuZ2Vsby5hc2VuY2lvQGktbmV0cGVydS5jb20ucGUJ
		$a_01_1 = {2f 00 69 00 6e 00 64 00 65 00 78 00 2e 00 70 00 68 00 70 00 3f 00 69 00 73 00 5f 00 70 00 32 00 70 00 65 00 6e 00 76 00 3d 00 5a 00 47 00 46 00 75 00 5a 00 32 00 56 00 73 00 62 00 79 00 35 00 68 00 63 00 32 00 56 00 75 00 59 00 32 00 6c 00 76 00 51 00 47 00 6b 00 74 00 62 00 6d 00 56 00 30 00 63 00 47 00 56 00 79 00 64 00 53 00 35 00 6a 00 62 00 32 00 30 00 75 00 63 00 47 00 55 00 4a 00 } //00 00  /index.php?is_p2penv=ZGFuZ2Vsby5hc2VuY2lvQGktbmV0cGVydS5jb20ucGUJ
	condition:
		any of ($a_*)
 
}