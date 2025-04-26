
rule TrojanDownloader_O97M_EncDoc_RVA_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.RVA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 69 6c 65 4e 6c 6d 65 20 3d 20 22 20 68 74 74 70 3a 2f 2f 77 77 77 2e 6a 2e 6d 70 2f 61 6a 64 } //1 FileNlme = " http://www.j.mp/ajd
		$a_01_1 = {53 68 65 6c 6c 25 20 5f 0d 0a 20 20 46 69 6c 65 4e 6f 6f 6d 65 20 2b 20 46 69 6c 65 4e 6c 6c 6d 65 2c 20 31 } //1
		$a_01_2 = {46 69 6c 65 4e 6f 6f 6d 65 20 3d 20 68 69 6c 6c 2e 46 69 6c 65 4e 78 6d 65 0d 0a 46 69 6c 65 4e 6c 6c 6d 65 20 3d 20 68 69 6c 6c 2e 46 69 6c 65 4e 6c 6d 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}