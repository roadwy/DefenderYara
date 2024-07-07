
rule TrojanDownloader_O97M_Obfuse_QV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.QV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {55 37 20 3d 20 55 37 20 2d 20 30 2e 30 30 30 30 30 30 30 30 30 30 33 20 2a 20 41 62 73 28 30 2e 38 32 39 33 39 36 30 38 35 30 35 20 2d 20 38 37 32 35 33 2e 31 37 37 31 33 30 31 35 35 20 2a 20 65 74 63 75 31 29 } //1 U7 = U7 - 0.00000000003 * Abs(0.82939608505 - 87253.177130155 * etcu1)
		$a_01_1 = {53 65 74 74 69 6e 67 41 74 74 72 2e 57 72 69 74 65 4c 69 6e 65 20 28 22 73 74 61 72 74 20 63 3a 5c 4c 6f 67 73 4d 6f 75 73 65 5c 70 73 69 63 6f 32 2e 65 78 65 22 29 } //1 SettingAttr.WriteLine ("start c:\LogsMouse\psico2.exe")
		$a_01_2 = {45 6c 65 76 61 74 65 64 54 72 75 65 46 61 6c 73 65 2e 54 65 6c 4e 75 6d 62 65 72 31 2e 43 61 70 74 69 6f 6e } //1 ElevatedTrueFalse.TelNumber1.Caption
		$a_03_3 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 22 63 3a 5c 4c 6f 67 73 4d 6f 75 73 65 5c 90 02 18 2e 63 6d 64 22 2c 20 54 72 75 65 29 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}