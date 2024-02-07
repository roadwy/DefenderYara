
rule TrojanDownloader_O97M_Obfuse_DRU_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.DRU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {43 68 72 28 34 36 29 20 2b 20 43 68 72 28 31 30 31 29 20 2b 20 43 68 72 28 31 32 30 29 20 2b 20 43 68 72 28 31 30 31 29 } //01 00  Chr(46) + Chr(101) + Chr(120) + Chr(101)
		$a_00_1 = {73 65 63 6f 6e 64 5f 6e 61 6d 65 20 3d 20 22 72 65 76 69 73 69 6f 6e 65 5f 63 6f 6e 74 61 62 69 6c 65 5f 32 30 31 39 22 } //01 00  second_name = "revisione_contabile_2019"
		$a_00_2 = {22 68 74 22 20 2b 20 22 74 70 22 20 2b 20 22 3a 22 20 2b 20 22 2f 22 20 2b 20 22 2f 22 20 2b 20 69 70 55 72 72 61 20 2b 20 22 2f 22 20 2b 20 70 61 79 5f 6e 61 6d 65 20 2b 20 65 78 74 5f 65 78 65 } //01 00  "ht" + "tp" + ":" + "/" + "/" + ipUrra + "/" + pay_name + ext_exe
		$a_00_3 = {70 61 79 5f 6e 61 6d 65 20 3d 20 22 73 69 6d 70 6c 65 5f 73 68 65 6c 6c 22 } //01 00  pay_name = "simple_shell"
		$a_00_4 = {66 69 72 73 74 5f 6f 63 74 20 2b 20 22 2e 22 20 2b 20 73 65 63 6f 6e 64 5f 6f 63 74 20 2b 20 22 2e 22 20 2b 20 74 68 69 72 64 5f 6f 63 74 20 2b 20 22 2e 22 20 2b 20 66 6f 75 72 74 68 5f 6f 63 74 } //01 00  first_oct + "." + second_oct + "." + third_oct + "." + fourth_oct
		$a_00_5 = {64 6f 77 6e 6c 6f 61 64 46 69 6c 65 28 29 } //01 00  downloadFile()
		$a_00_6 = {72 65 6e 61 6d 65 46 69 6c 65 28 29 } //00 00  renameFile()
	condition:
		any of ($a_*)
 
}