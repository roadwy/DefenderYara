
rule TrojanDownloader_O97M_Encdoc_AK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Encdoc.AK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 3a 2f 2f 64 65 76 2e 6b 61 74 65 76 69 63 74 6f 72 69 61 62 65 61 75 74 79 2e 63 6f 2e 75 6b 2f 67 70 68 78 74 62 69 2f 35 33 30 33 34 30 2e 70 6e 67 } //01 00  http://dev.katevictoriabeauty.co.uk/gphxtbi/530340.png
		$a_00_1 = {4a 4a 43 43 43 4a } //01 00  JJCCCJ
		$a_00_2 = {64 54 6f 46 69 6c 65 41 } //01 00  dToFileA
		$a_00_3 = {43 3a 5c 44 61 74 6f 70 5c } //00 00  C:\Datop\
	condition:
		any of ($a_*)
 
}