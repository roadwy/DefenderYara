
rule Trojan_Win64_DonutLoader_PCO_MTB{
	meta:
		description = "Trojan:Win64/DonutLoader.PCO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_03_0 = {31 00 34 00 31 00 2e 00 39 00 38 00 2e 00 36 00 2e 00 31 00 34 00 3a 00 35 00 35 00 36 00 33 00 2f 00 [0-07] 2e 00 65 00 78 00 65 00 } //2
		$a_03_1 = {31 34 31 2e 39 38 2e 36 2e 31 34 3a 35 35 36 33 2f [0-07] 2e 65 78 65 } //2
		$a_81_2 = {65 78 65 63 75 74 65 50 6f 77 65 72 53 68 65 6c 6c } //1 executePowerShell
		$a_81_3 = {64 6f 77 6e 6c 6f 61 64 41 6e 64 52 75 6e 46 69 6c 65 } //1 downloadAndRunFile
		$a_81_4 = {63 72 65 61 74 65 52 61 6e 64 6f 6d 46 6f 6c 64 65 72 49 6e 41 70 70 44 61 74 61 4c 6f 63 61 6c } //2 createRandomFolderInAppDataLocal
		$a_81_5 = {41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 } //1 Add-MpPreference -ExclusionPath
		$a_81_6 = {72 65 73 74 61 72 74 41 73 41 64 6d 69 6e } //1 restartAsAdmin
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*2+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=8
 
}