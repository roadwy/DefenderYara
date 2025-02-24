
rule Trojan_BAT_LummaC_AYA_MTB{
	meta:
		description = "Trojan:BAT/LummaC.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 08 00 00 "
		
	strings :
		$a_01_0 = {24 61 62 33 38 32 33 33 39 2d 63 32 39 62 2d 34 35 36 30 2d 61 66 32 36 2d 61 30 66 66 39 37 31 38 37 34 32 65 } //3 $ab382339-c29b-4560-af26-a0ff9718742e
		$a_01_1 = {74 65 73 74 72 65 76 65 72 73 65 70 72 6f 78 79 } //1 testreverseproxy
		$a_01_2 = {41 64 64 46 6f 6c 64 65 72 54 6f 44 65 66 65 6e 64 65 72 45 78 63 6c 75 73 69 6f 6e 73 } //1 AddFolderToDefenderExclusions
		$a_01_3 = {47 65 6e 65 72 61 74 65 52 61 6e 64 6f 6d 46 69 6c 65 4e 61 6d 65 } //1 GenerateRandomFileName
		$a_01_4 = {47 65 6e 65 72 61 74 65 52 61 6e 64 6f 6d 46 6f 6c 64 65 72 4e 61 6d 65 } //1 GenerateRandomFolderName
		$a_01_5 = {49 73 52 75 6e 41 73 41 64 6d 69 6e } //1 IsRunAsAdmin
		$a_01_6 = {52 65 73 74 61 72 74 41 73 41 64 6d 69 6e } //1 RestartAsAdmin
		$a_00_7 = {43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 20 00 22 00 41 00 64 00 64 00 2d 00 4d 00 70 00 50 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 20 00 2d 00 45 00 78 00 63 00 6c 00 75 00 73 00 69 00 6f 00 6e 00 50 00 61 00 74 00 68 00 } //1 Command "Add-MpPreference -ExclusionPath
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_00_7  & 1)*1) >=10
 
}