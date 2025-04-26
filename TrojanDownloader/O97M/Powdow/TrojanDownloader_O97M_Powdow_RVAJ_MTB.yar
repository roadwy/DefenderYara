
rule TrojanDownloader_O97M_Powdow_RVAJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVAJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 = CreateObject("WScript.Shell")
		$a_03_1 = {2e 4f 70 65 6e 20 22 70 6f 73 74 22 2c 20 [0-64] 28 22 68 ?? ?? ?? ?? 3a 2f 2f 6a [0-64] 22 29 2c 20 46 61 6c 73 65 } //1
		$a_03_2 = {49 6e 53 74 72 28 [0-64] 2c 20 4d 69 64 28 [0-64] 2c 20 69 2c 20 31 29 29 } //1
		$a_01_3 = {3d 20 43 68 72 28 35 30 29 20 2b 20 43 68 72 28 34 38 29 20 2b 20 43 68 72 28 34 38 29 } //1 = Chr(50) + Chr(48) + Chr(48)
		$a_01_4 = {52 61 6e 67 65 28 22 41 31 22 29 2e 56 61 6c 75 65 20 3d 20 22 6f 6b 2e 2e 2e 2e 2e 2e 2e 22 } //1 Range("A1").Value = "ok......."
		$a_01_5 = {3d 20 57 73 68 53 68 65 6c 6c 2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 22 52 65 63 65 6e 74 22 29 } //1 = WshShell.SpecialFolders("Recent")
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}