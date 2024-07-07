
rule TrojanDownloader_O97M_Powdow_BKL_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.BKL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {76 6c 73 20 3d 20 76 6c 73 20 26 } //1 vls = vls &
		$a_01_1 = {3d 20 43 68 72 28 66 64 73 67 20 2d 20 31 32 32 29 } //1 = Chr(fdsg - 122)
		$a_01_2 = {2e 52 75 6e 28 69 6b 6e 72 77 72 6f 70 72 71 70 73 6d 72 67 79 2c 20 61 68 72 7a 72 78 69 71 64 6c 6c 75 6f 66 75 78 6c 6d 7a 6d 69 6b 72 79 74 6a 63 6c 77 74 6b 61 77 69 29 } //1 .Run(iknrwroprqpsmrgy, ahrzrxiqdlluofuxlmzmikrytjclwtkawi)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}