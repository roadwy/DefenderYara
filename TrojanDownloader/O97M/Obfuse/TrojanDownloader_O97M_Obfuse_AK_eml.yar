
rule TrojanDownloader_O97M_Obfuse_AK_eml{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.AK!eml,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 } //1 Sub Document_Open()
		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 4d 69 64 28 6d 67 73 2e 43 6f 75 6e 74 50 61 67 65 73 2e 50 61 67 65 32 2e 52 75 6e 54 65 78 74 42 6f 78 2e 56 61 6c 75 65 2c 20 39 2c 20 31 37 29 29 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 74 68 69 6e 67 } //1 CreateObject(Mid(mgs.CountPages.Page2.RunTextBox.Value, 9, 17)).ShellExecute thing
		$a_01_2 = {77 61 6e 74 74 6f 73 6c 65 65 70 20 3d 20 77 61 6e 74 74 6f 73 6c 65 65 70 20 26 20 66 75 6c 6c 4c } //1 wanttosleep = wanttosleep & fullL
		$a_01_3 = {6f 74 68 65 72 74 68 69 6e 68 20 28 74 65 6d 70 56 29 } //1 otherthinh (tempV)
		$a_01_4 = {66 75 6a 69 20 74 65 6d 70 56 2c 20 69 64 6f 6e 74 6b 6e 6f 77 } //1 fuji tempV, idontknow
		$a_01_5 = {3d 20 72 65 2e 53 74 61 72 74 } //1 = re.Start
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule TrojanDownloader_O97M_Obfuse_AK_eml_2{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.AK!eml,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {2e 49 74 65 6d 28 29 2e 44 6f 63 75 6d 65 6e 74 2e 41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 90 02 1a 2c 20 90 02 1c 20 26 20 90 02 1b 2c 20 90 02 1e 28 90 00 } //1
		$a_01_1 = {73 68 75 72 6c 20 3d 20 56 61 6c 28 52 65 70 6c 61 63 65 28 22 4f 22 2c 20 22 4f 22 2c 20 22 26 22 29 20 26 20 52 65 70 6c 61 63 65 28 22 68 22 2c 20 22 68 22 2c 20 22 48 22 29 20 26 20 4d 69 64 28 } //1 shurl = Val(Replace("O", "O", "&") & Replace("h", "h", "H") & Mid(
		$a_01_2 = {63 72 75 6c 20 3d 20 43 68 72 28 73 68 75 72 6c 29 } //1 crul = Chr(shurl)
		$a_03_3 = {49 66 20 28 56 61 6c 28 41 70 70 6c 69 63 61 74 69 6f 6e 2e 56 65 72 73 69 6f 6e 29 29 20 54 68 65 6e 90 02 1e 20 3d 20 41 72 72 61 79 28 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}