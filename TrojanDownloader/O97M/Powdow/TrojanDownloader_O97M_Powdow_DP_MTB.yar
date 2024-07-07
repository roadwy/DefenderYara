
rule TrojanDownloader_O97M_Powdow_DP_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.DP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4d 65 2e 52 65 70 61 69 6e 74 } //1 Me.Repaint
		$a_01_1 = {55 6e 6c 6f 61 64 20 4d 65 } //1 Unload Me
		$a_01_2 = {74 69 6d 65 32 20 3d 20 4e 6f 77 20 2b 20 54 69 6d 65 56 61 6c 75 65 28 22 30 3a 30 30 3a 30 33 22 29 } //1 time2 = Now + TimeValue("0:00:03")
		$a_01_3 = {52 45 74 61 73 20 3d 20 45 6e 76 69 72 6f 6e 28 54 65 72 69 6f 6c 2e 43 61 70 74 69 6f 6e 29 } //1 REtas = Environ(Teriol.Caption)
		$a_01_4 = {53 68 65 6c 6c 20 22 63 6d 64 20 2f 63 22 20 26 20 52 45 74 61 73 20 26 20 54 72 65 73 74 2e 54 61 67 2c 20 30 } //1 Shell "cmd /c" & REtas & Trest.Tag, 0
		$a_01_5 = {48 65 72 74 69 20 3d 20 52 45 74 61 73 20 26 20 54 72 65 73 74 2e 54 61 67 } //1 Herti = REtas & Trest.Tag
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}