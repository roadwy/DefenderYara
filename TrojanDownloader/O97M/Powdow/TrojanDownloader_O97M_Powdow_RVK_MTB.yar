
rule TrojanDownloader_O97M_Powdow_RVK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 69 6e 6b 20 3d 20 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 62 69 74 6c 79 2e 63 6f 6d 2f 61 64 } //01 00  link = "https://www.bitly.com/ad
		$a_01_1 = {6d 69 6c 6c 20 3d 20 6f 20 2b 20 6d 20 2b 20 6c 20 2b 20 61 20 2b 20 69 } //01 00  mill = o + m + l + a + i
		$a_01_2 = {2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 4d 73 67 42 6f 78 2e 6d 69 6c 6c 2c 20 4d 73 67 42 6f 78 2e 6c 69 6e 6b } //00 00  .ShellExecute MsgBox.mill, MsgBox.link
	condition:
		any of ($a_*)
 
}