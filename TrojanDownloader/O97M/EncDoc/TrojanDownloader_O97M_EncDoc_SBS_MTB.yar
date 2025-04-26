
rule TrojanDownloader_O97M_EncDoc_SBS_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SBS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 69 63 72 6f 73 6f 66 74 2e 58 4d 4c 48 54 54 50 22 29 } //1 = CreateObject("Microsoft.XMLHTTP")
		$a_01_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 41 64 6f 64 62 2e 53 74 72 65 61 6d 22 29 } //1 = CreateObject("Adodb.Stream")
		$a_03_2 = {2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 [0-5a] 2e 65 78 65 22 2c } //1
		$a_03_3 = {53 68 65 6c 6c 20 28 22 [0-2f] 2e 65 78 65 22 29 } //1
		$a_03_4 = {2e 73 61 76 65 74 6f 66 69 6c 65 20 22 [0-2f] 2e 65 78 65 22 2c 20 32 20 27 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}