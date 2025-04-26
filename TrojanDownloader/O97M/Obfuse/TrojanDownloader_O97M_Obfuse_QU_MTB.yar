
rule TrojanDownloader_O97M_Obfuse_QU_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.QU!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4b 69 6f 72 74 6e 72 72 20 3d 20 4b 69 6f 72 74 6e 72 72 20 2b 20 30 2e 31 31 31 30 37 36 35 39 37 38 20 2a 20 43 53 67 6e 28 33 2e 39 36 32 30 35 30 39 30 31 39 34 20 2b 20 32 31 33 2e 32 39 39 30 39 35 34 33 38 20 2a 20 4a 29 } //1 Kiortnrr = Kiortnrr + 0.1110765978 * CSgn(3.96205090194 + 213.299095438 * J)
		$a_01_1 = {42 65 6f 6d 65 74 72 69 63 6b 31 2e 57 72 69 74 65 4c 69 6e 65 20 28 22 73 74 61 72 74 20 63 3a 5c 52 65 73 6f 75 72 63 65 73 5c 52 45 44 63 6c 69 66 2e 65 78 65 22 29 } //1 Beometrick1.WriteLine ("start c:\Resources\REDclif.exe")
		$a_01_2 = {6d 79 55 73 65 72 46 6f 72 6d 31 2e 50 68 6f 6e 65 2e 43 61 70 74 69 6f 6e 29 } //1 myUserForm1.Phone.Caption)
		$a_03_3 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 22 63 3a 5c 52 65 73 6f 75 72 63 65 73 5c [0-18] 2e 63 6d 64 22 2c 20 54 72 75 65 29 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}