
rule TrojanDownloader_O97M_Obfuse_SNS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.SNS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 41 75 74 6f 5f 43 6c 6f 73 65 28 29 } //1 Sub Auto_Close()
		$a_01_1 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 6b 55 4c 4c 49 6c 75 6c 6c 69 6b 68 61 6f 29 } //1 = GetObject(kULLIlullikhao)
		$a_01_2 = {2e 63 6f 70 79 66 69 6c 65 20 6c 6f 72 61 6b 61 6c 61 2c 20 77 69 6e 67 61 64 75 6d 6c 65 76 69 6f 73 61 2c 20 54 72 75 65 } //1 .copyfile lorakala, wingadumleviosa, True
		$a_01_3 = {3d 20 22 43 3a 5c 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 5c 64 64 6f 6e 64 2e 63 6f 6d 20 68 74 74 70 73 3a 2f 2f 74 61 78 66 69 6c 65 2e 6d 65 64 69 61 66 69 72 65 2e 63 6f 6d 2f 22 20 2b 20 22 66 69 6c 65 2f 38 37 6a 33 62 6a 30 6b 73 30 61 73 75 35 38 2f 33 2e 68 74 6d 2f 66 69 6c 65 22 } //1 = "C:\\ProgramData\\ddond.com https://taxfile.mediafire.com/" + "file/87j3bj0ks0asu58/3.htm/file"
		$a_01_4 = {43 61 6c 6c 20 56 42 41 2e 53 68 65 6c 6c 23 28 6b 61 6c 69 6d 75 74 68 29 } //1 Call VBA.Shell#(kalimuth)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}