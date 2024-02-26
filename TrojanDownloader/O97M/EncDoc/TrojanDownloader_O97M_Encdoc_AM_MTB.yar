
rule TrojanDownloader_O97M_Encdoc_AM_MTB{
	meta:
		description = "TrojanDownloader:O97M/Encdoc.AM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 67 72 61 63 65 66 75 6c 6c 69 66 65 74 69 6d 65 2e 63 6f 6d 2f 79 71 61 67 74 69 6c 6a 67 6b 2f 35 33 30 33 34 30 2e 70 6e 67 } //01 00  http://gracefullifetime.com/yqagtiljgk/530340.png
		$a_00_1 = {4a 4a 43 43 43 4a } //01 00  JJCCCJ
		$a_00_2 = {64 54 6f 46 69 6c 65 41 } //00 00  dToFileA
	condition:
		any of ($a_*)
 
}