
rule TrojanDownloader_O97M_IcedID_PCO_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedID.PCO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {2e 53 65 6e 64 } //1 .Send
		$a_00_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //1 CreateObject("wscript.shell")
		$a_02_2 = {2e 65 78 65 63 20 28 90 02 0a 29 90 00 } //1
		$a_00_3 = {2e 66 63 63 64 62 39 33 33 20 61 38 61 39 62 61 37 30 28 30 29 20 2b 20 22 20 22 20 2b 20 65 39 66 33 34 32 33 65 28 22 70 64 66 22 29 } //1 .fccdb933 a8a9ba70(0) + " " + e9f3423e("pdf")
		$a_02_4 = {53 70 6c 69 74 28 90 02 0a 2c 20 22 7c 22 29 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_IcedID_PCO_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/IcedID.PCO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //1 CreateObject("wscript.shell")
		$a_02_1 = {2e 65 78 65 63 20 28 90 02 0a 29 90 00 } //1
		$a_02_2 = {3d 20 53 70 6c 69 74 28 90 02 0a 2c 20 22 7c 22 29 90 00 } //1
		$a_00_3 = {2e 6a 70 67 22 } //1 .jpg"
		$a_02_4 = {3d 20 53 74 72 43 6f 6e 76 28 90 02 0a 2c 20 76 62 55 6e 69 63 6f 64 65 29 90 00 } //1
		$a_00_5 = {2e 4f 70 65 6e 20 22 47 45 54 22 2c } //1 .Open "GET",
		$a_00_6 = {28 30 29 20 2b 20 22 20 22 20 2b 20 } //1 (0) + " " + 
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}