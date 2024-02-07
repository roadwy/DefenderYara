
rule TrojanDownloader_O97M_IcedID_PCO_MTB{
	meta:
		description = "TrojanDownloader:O97M/IcedID.PCO!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {2e 53 65 6e 64 } //01 00  .Send
		$a_00_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 } //01 00  CreateObject("wscript.shell")
		$a_02_2 = {2e 65 78 65 63 20 28 90 02 0a 29 90 00 } //01 00 
		$a_00_3 = {2e 66 63 63 64 62 39 33 33 20 61 38 61 39 62 61 37 30 28 30 29 20 2b 20 22 20 22 20 2b 20 65 39 66 33 34 32 33 65 28 22 70 64 66 22 29 } //01 00  .fccdb933 a8a9ba70(0) + " " + e9f3423e("pdf")
		$a_02_4 = {53 70 6c 69 74 28 90 02 0a 2c 20 22 7c 22 29 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}