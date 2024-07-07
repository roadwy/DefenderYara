
rule TrojanDownloader_O97M_Powdow_CTYQ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.CTYQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 63 75 74 74 2e 6c 79 2f 76 6b 6e 6b 6d 69 51 } //1 http://cutt.ly/vknkmiQ
		$a_01_1 = {74 74 70 3a 2f 2f 72 65 62 72 61 6e 64 2e 6c 79 2f 57 64 42 50 41 70 6f 4d 41 43 52 4f } //1 ttp://rebrand.ly/WdBPApoMACRO
		$a_01_2 = {28 6e 45 77 2d 6f 42 60 6a 65 63 54 20 4e 65 } //1 (nEw-oB`jecT Ne
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}