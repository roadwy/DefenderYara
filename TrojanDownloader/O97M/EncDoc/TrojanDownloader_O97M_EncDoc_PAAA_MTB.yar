
rule TrojanDownloader_O97M_EncDoc_PAAA_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PAAA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {65 3d 22 6d 6f 64 75 6c 65 31 22 73 75 62 61 75 74 6f 5f 6f 70 65 6e 28 29 73 65 74 6f 75 74 6c 6f 6f 6b 3d 63 72 65 61 74 65 6f 62 6a 65 63 74 28 79 6f 63 61 6b 6f 76 7a 74 } //1 e="module1"subauto_open()setoutlook=createobject(yocakovzt
		$a_01_1 = {22 2c 22 36 22 29 2b 63 68 72 28 31 35 30 29 2b 79 6f 63 61 6b 6f 76 7a 74 28 22 } //1 ","6")+chr(150)+yocakovzt("
		$a_01_2 = {70 70 36 69 66 63 70 6c 39 2c 31 29 3d 63 68 72 28 61 73 63 28 6d 69 64 28 64 67 68 6b 6b 6b 78 6b 73 2c 70 70 36 69 66 63 70 6c 39 2c 31 29 29 2d 6e 64 66 66 65 63 76 65 70 29 6e 65 78 74 70 70 36 69 66 63 70 6c 39 } //1 pp6ifcpl9,1)=chr(asc(mid(dghkkkxks,pp6ifcpl9,1))-ndffecvep)nextpp6ifcpl9
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}