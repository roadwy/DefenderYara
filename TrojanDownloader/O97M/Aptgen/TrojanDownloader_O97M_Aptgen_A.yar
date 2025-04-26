
rule TrojanDownloader_O97M_Aptgen_A{
	meta:
		description = "TrojanDownloader:O97M/Aptgen.A,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 08 00 00 "
		
	strings :
		$a_00_0 = {20 3d 20 75 73 70 61 63 75 74 28 22 44 6e 61 65 6e 61 63 6e 61 72 6e 61 79 6e 61 70 6e 61 74 6e 61 69 6e 61 6f 6e 61 6e 6e 61 } //1  = uspacut("Dnaenacnarnaynapnatnainaonanna
		$a_00_1 = {20 3d 20 69 6b 6f 78 73 28 22 44 70 61 73 65 70 61 73 63 70 61 73 72 70 61 73 79 70 61 73 70 70 61 73 74 70 61 73 69 70 61 73 6f 70 61 73 6e 70 61 73 } //1  = ikoxs("Dpasepascpasrpasypasppastpasipasopasnpas
		$a_00_2 = {20 3d 20 52 65 70 6c 61 63 65 28 22 44 6f 68 65 6f 68 63 6f 68 72 6f 68 79 6f 68 70 6f 68 74 6f 68 69 6f 68 6f 6f 68 6e 6f 68 } //1  = Replace("Doheohcohrohyohpohtohiohoohnoh
		$a_00_3 = {20 3d 20 52 65 70 6c 61 63 65 28 22 44 6e 75 70 6c 65 6e 75 70 6c 63 6e 75 70 6c 72 6e 75 70 6c 79 6e 75 70 6c 70 6e 75 70 6c 74 6e 75 70 6c 69 6e 75 70 6c 6f 6e 75 70 6c 6e 6e 75 70 6c } //1  = Replace("Dnuplenuplcnuplrnuplynuplpnupltnuplinuplonuplnnupl
		$a_00_4 = {20 3d 20 6a 74 79 6b 70 79 70 65 2e 47 65 74 46 6f 6c 64 65 72 28 61 67 75 6c 75 2e 65 78 70 61 6e 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 28 22 25 50 52 4f 47 52 41 4d 46 49 4c 45 53 25 22 29 29 } //1  = jtykpype.GetFolder(agulu.expandEnvironmentStrings("%PROGRAMFILES%"))
		$a_00_5 = {71 20 3d 20 45 6e 76 69 72 6f 6e 28 22 75 73 65 72 70 72 6f 66 69 6c 65 22 29 20 26 20 70 28 32 29 0d 0a 46 69 6c 65 43 6f 70 79 20 70 28 31 29 2c 20 71 0d 0a 53 68 65 6c 6c 20 71 20 26 20 70 28 33 29 2c 20 30 } //1
		$a_00_6 = {73 73 75 67 79 6d 20 3d 20 22 77 73 63 72 69 22 20 26 20 62 78 65 6b 6f 20 26 20 22 78 65 20 22 20 26 20 6f 74 6b 79 62 77 20 26 20 22 73 63 72 69 70 74 20 22 20 26 20 77 6f 6c 79 78 } //1 ssugym = "wscri" & bxeko & "xe " & otkybw & "script " & wolyx
		$a_00_7 = {63 61 63 7a 77 63 20 3d 20 41 72 72 61 79 28 33 36 37 2c 20 33 35 38 2c 20 33 36 37 2c 20 33 37 31 2c 20 33 35 38 2c 20 33 36 33 2c 20 33 36 34 2c 20 33 36 37 2c 20 33 35 38 29 } //1 caczwc = Array(367, 358, 367, 371, 358, 363, 364, 367, 358)
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=1
 
}