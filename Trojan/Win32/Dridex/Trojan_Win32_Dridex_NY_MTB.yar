
rule Trojan_Win32_Dridex_NY_MTB{
	meta:
		description = "Trojan:Win32/Dridex.NY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 09 00 00 08 00 "
		
	strings :
		$a_02_0 = {8b 4c 24 40 8a 90 02 06 32 90 02 06 8b 90 02 06 88 90 02 06 0f 90 02 03 0f 90 02 07 29 90 01 01 8b 90 02 06 89 90 02 02 89 90 02 03 89 90 02 03 e8 90 00 } //01 00 
		$a_81_1 = {73 65 6c 66 2e 65 78 } //01 00  self.ex
		$a_81_2 = {41 76 69 72 61 20 47 6d 62 48 } //01 00  Avira GmbH
		$a_81_3 = {66 65 72 36 65 35 2e 70 64 62 } //01 00  fer6e5.pdb
		$a_81_4 = {52 65 67 4c 6f 61 64 41 70 70 4b 65 79 57 } //01 00  RegLoadAppKeyW
		$a_81_5 = {4f 75 74 70 75 74 44 65 62 75 67 53 74 72 69 6e 67 41 } //01 00  OutputDebugStringA
		$a_81_6 = {44 62 6e 6f 65 65 75 66 68 74 68 72 61 20 46 68 61 74 78 } //01 00  Dbnoeeufhthra Fhatx
		$a_81_7 = {6d 61 6e 69 70 75 6c 61 74 69 6f 6e 73 76 66 72 65 64 74 68 65 48 69 67 68 72 65 6d 6f 76 65 64 66 39 } //01 00  manipulationsvfredtheHighremovedf9
		$a_81_8 = {53 61 64 4d 43 68 72 6f 6d 69 75 6d 76 65 72 73 69 6f 6e } //00 00  SadMChromiumversion
	condition:
		any of ($a_*)
 
}