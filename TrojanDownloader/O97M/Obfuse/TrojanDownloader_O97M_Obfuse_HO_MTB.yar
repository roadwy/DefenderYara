
rule TrojanDownloader_O97M_Obfuse_HO_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.HO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 61 76 65 32 66 69 6c 65 20 3d 20 70 65 6f 70 65 70 65 70 65 70 65 20 26 20 43 68 72 28 39 32 29 20 26 20 52 6e 64 20 26 20 22 2e 6a 73 65 22 } //01 00  save2file = peopepepepe & Chr(92) & Rnd & ".jse"
		$a_01_1 = {53 65 74 20 73 68 65 6c 6c 4f 62 6a 20 3d 20 6f 62 6a 4f 4c 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 2c 20 22 22 29 } //01 00  Set shellObj = objOL.CreateObject("Shell.Application", "")
		$a_01_2 = {73 68 65 6c 6c 4f 62 6a 2e 53 68 65 6c 6c 45 78 65 63 75 74 65 20 73 61 76 65 32 66 69 6c 65 } //01 00  shellObj.ShellExecute save2file
		$a_01_3 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 73 61 76 65 32 66 69 6c 65 2c 20 54 72 75 65 2c 20 54 72 75 65 29 } //00 00  .CreateTextFile(save2file, True, True)
	condition:
		any of ($a_*)
 
}