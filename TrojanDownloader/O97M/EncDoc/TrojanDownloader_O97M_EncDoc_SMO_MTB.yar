
rule TrojanDownloader_O97M_EncDoc_SMO_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SMO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 69 73 6d 61 69 6c 69 79 61 6d 65 64 69 63 61 6c 2e 63 6f 6d 2f 64 73 2f 31 35 31 31 32 30 2e 67 69 66 } //1 http://ismailiyamedical.com/ds/151120.gif
		$a_01_1 = {68 74 74 70 73 3a 2f 2f 65 73 70 2e 61 64 6e 61 6e 2e 64 65 76 2e 68 6f 73 74 69 6e 67 73 68 6f 75 73 65 2e 63 6f 6d 2f 64 73 2f 31 35 31 31 32 30 2e 67 69 66 } //1 https://esp.adnan.dev.hostingshouse.com/ds/151120.gif
		$a_01_2 = {4a 4a 43 43 43 43 4a } //1 JJCCCCJ
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}