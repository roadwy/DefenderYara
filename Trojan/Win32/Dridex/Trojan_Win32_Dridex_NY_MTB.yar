
rule Trojan_Win32_Dridex_NY_MTB{
	meta:
		description = "Trojan:Win32/Dridex.NY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 09 00 00 "
		
	strings :
		$a_02_0 = {8b 4c 24 40 8a [0-06] 32 [0-06] 8b [0-06] 88 [0-06] 0f [0-03] 0f [0-07] 29 ?? 8b [0-06] 89 [0-02] 89 [0-03] 89 [0-03] e8 } //8
		$a_81_1 = {73 65 6c 66 2e 65 78 } //1 self.ex
		$a_81_2 = {41 76 69 72 61 20 47 6d 62 48 } //1 Avira GmbH
		$a_81_3 = {66 65 72 36 65 35 2e 70 64 62 } //1 fer6e5.pdb
		$a_81_4 = {52 65 67 4c 6f 61 64 41 70 70 4b 65 79 57 } //1 RegLoadAppKeyW
		$a_81_5 = {4f 75 74 70 75 74 44 65 62 75 67 53 74 72 69 6e 67 41 } //1 OutputDebugStringA
		$a_81_6 = {44 62 6e 6f 65 65 75 66 68 74 68 72 61 20 46 68 61 74 78 } //1 Dbnoeeufhthra Fhatx
		$a_81_7 = {6d 61 6e 69 70 75 6c 61 74 69 6f 6e 73 76 66 72 65 64 74 68 65 48 69 67 68 72 65 6d 6f 76 65 64 66 39 } //1 manipulationsvfredtheHighremovedf9
		$a_81_8 = {53 61 64 4d 43 68 72 6f 6d 69 75 6d 76 65 72 73 69 6f 6e } //1 SadMChromiumversion
	condition:
		((#a_02_0  & 1)*8+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=8
 
}