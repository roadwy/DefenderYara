
rule TrojanDownloader_O97M_Powdow_ALT_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.ALT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 75 6e 63 74 69 6f 6e 20 72 68 7a 6d 65 58 54 28 66 67 66 6a 68 66 67 66 67 2c 20 66 64 34 35 63 76 76 30 29 } //1 Function rhzmeXT(fgfjhfgfg, fd45cvv0)
		$a_01_1 = {49 45 68 79 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 22 50 22 20 2b 20 66 64 34 35 63 76 76 30 2c 20 66 67 66 6a 68 66 67 66 67 2c 20 22 22 2c 20 22 22 2c 20 30 } //1 IEhy.ShellExecute "P" + fd45cvv0, fgfjhfgfg, "", "", 0
		$a_01_2 = {27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 27 4d 73 67 42 6f 78 } //1 'MsgBox'MsgBox'MsgBox'MsgBox'MsgBox'MsgBox'MsgBox
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Powdow_ALT_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.ALT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {66 68 6b 73 20 3d 20 22 6a 4c 77 43 6a 4c 77 3a 6a 4c 77 5c 6a 4c 77 57 6a 4c 77 69 6a 4c 77 6e 64 6a 4c 77 6f 77 6a 4c 77 73 5c 53 6a 4c 77 79 73 6a 4c 77 74 65 6a 4c 77 6d 33 6a 4c 77 32 5c 63 6a 4c 77 6d 6a 4c 77 64 2e 6a 4c 77 65 6a 4c 77 78 6a 4c 77 65 } //1 fhks = "jLwCjLw:jLw\jLwWjLwijLwndjLwowjLws\SjLwysjLwtejLwm3jLw2\cjLwmjLwd.jLwejLwxjLwe
		$a_01_1 = {72 68 71 77 6f 65 6c 68 73 6c 64 20 3d 20 52 65 70 6c 61 63 65 28 6a 6c 76 66 64 2c 20 62 78 63 6a 2c 20 22 22 29 } //1 rhqwoelhsld = Replace(jlvfd, bxcj, "")
		$a_01_2 = {66 6f 6a 6e 20 3d 20 65 72 74 6a 77 6c 6b 66 6a 28 30 2c 20 22 22 2c 20 22 22 2c 20 30 2c 20 30 29 } //1 fojn = ertjwlkfj(0, "", "", 0, 0)
		$a_01_3 = {77 65 72 20 3d 20 74 65 20 2b 20 53 68 65 6c 6c 28 68 6b 69 77 65 20 2b 20 22 20 22 20 2b 20 77 6b 6a 68 2c 20 30 29 } //1 wer = te + Shell(hkiwe + " " + wkjh, 0)
		$a_01_4 = {4d 73 67 42 6f 78 20 22 71 33 34 } //1 MsgBox "q34
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Powdow_ALT_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Powdow.ALT!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {3d 20 45 6e 76 69 72 6f 6e 24 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 20 26 20 22 5c 22 20 26 } //1 = Environ$("USERPROFILE") & "\" &
		$a_01_1 = {3d 20 43 68 72 28 35 30 29 20 2b 20 43 68 72 28 34 38 29 20 2b 20 43 68 72 28 34 38 29 } //1 = Chr(50) + Chr(48) + Chr(48)
		$a_03_2 = {53 65 74 20 57 73 68 53 68 65 6c 6c 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 90 02 20 53 70 65 63 69 61 6c 50 61 74 68 20 3d 20 57 73 68 53 68 65 6c 6c 2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 22 52 65 63 65 6e 74 22 29 90 00 } //1
		$a_03_3 = {2e 53 74 61 74 75 73 20 3d 20 32 30 30 20 54 68 65 6e 90 0c 02 00 53 65 74 90 00 } //1
		$a_03_4 = {46 75 6e 63 74 69 6f 6e 20 90 02 35 28 29 20 41 73 20 90 02 10 43 61 6c 6c 20 90 02 40 45 6e 64 20 46 75 6e 63 74 69 6f 6e 90 00 } //1
		$a_03_5 = {69 2c 20 31 29 90 02 20 45 6e 64 20 49 66 90 02 20 4e 65 78 74 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}