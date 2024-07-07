
rule TrojanDownloader_O97M_Obfuse_SRV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SRV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 22 65 78 70 6c 6f 72 65 72 20 63 6f 70 79 46 75 6e 63 74 69 6f 6e 2e 68 74 61 22 2c 20 76 62 4e 6f 72 6d 61 6c 46 6f 63 75 73 } //2 Shell "explorer copyFunction.hta", vbNormalFocus
		$a_01_1 = {53 68 65 6c 6c 20 22 65 78 70 6c 6f 72 65 72 20 62 6f 6f 6c 65 61 6e 5a 65 72 6f 43 2e 68 74 61 22 2c 20 76 62 4e 6f 72 6d 61 6c 46 6f 63 75 73 } //2 Shell "explorer booleanZeroC.hta", vbNormalFocus
		$a_01_2 = {4f 70 65 6e 20 22 63 6f 70 79 46 75 6e 63 74 69 6f 6e 2e 68 74 61 22 20 26 20 62 75 74 74 6f 6e 52 65 66 65 72 65 6e 63 65 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31 } //2 Open "copyFunction.hta" & buttonReference For Output As #1
		$a_01_3 = {4f 70 65 6e 20 22 62 6f 6f 6c 65 61 6e 5a 65 72 6f 43 2e 68 74 61 22 20 26 20 62 75 74 74 6f 6e 52 65 66 65 72 65 6e 63 65 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31 } //2 Open "booleanZeroC.hta" & buttonReference For Output As #1
		$a_01_4 = {50 72 69 6e 74 20 23 31 2c 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 52 61 6e 67 65 2e 54 65 78 74 } //1 Print #1, ActiveDocument.Range.Text
		$a_01_5 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 0d 0a 63 6c 65 61 72 53 63 72 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}