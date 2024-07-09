
rule TrojanDownloader_O97M_Rietspoof_A{
	meta:
		description = "TrojanDownloader:O97M/Rietspoof.A,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {2e 52 65 67 57 72 69 74 65 20 [0-20] 2c [0-20] 2c [0-20] 28 22 [0-20] 22 29 20 26 20 [0-20] 28 22 [0-04] 22 29 } //1
		$a_01_1 = {41 63 74 69 76 65 57 69 6e 64 6f 77 2e 56 69 65 77 2e 53 68 6f 77 48 69 64 64 65 6e 54 65 78 74 20 3d 20 54 72 75 65 } //1 ActiveWindow.View.ShowHiddenText = True
		$a_01_2 = {3d 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 74 61 72 74 75 70 50 61 74 68 20 2b 20 } //1 = Application.StartupPath + 
		$a_03_3 = {3d 20 53 68 65 6c 6c 28 22 77 73 63 72 69 70 74 2e 65 78 65 20 22 22 22 20 2b 20 [0-20] 20 2b 20 22 22 2c 20 76 62 48 69 64 65 29 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}