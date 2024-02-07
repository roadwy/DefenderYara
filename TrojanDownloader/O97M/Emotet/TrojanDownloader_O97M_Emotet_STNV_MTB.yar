
rule TrojanDownloader_O97M_Emotet_STNV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.STNV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 61 67 69 72 2d 73 61 6e 74 65 69 6e 74 65 72 6e 61 74 69 6f 6e 61 6c 65 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 53 55 68 55 72 55 42 72 4b 34 32 4e 2f } //01 00  ://agir-santeinternationale.com/wp-admin/SUhUrUBrK42N/
		$a_01_1 = {3a 2f 2f 61 6c 7a 68 65 69 6d 65 72 7a 61 6d 6f 72 61 2e 63 6f 6d 2f 6c 69 62 72 61 72 69 65 73 2f 63 6f 6c 6f 72 62 75 74 74 6f 6e 2f 69 63 6f 6e 73 2f 68 69 64 70 69 2f 41 59 5a 52 46 54 48 6b 62 6a 35 30 35 68 41 33 41 71 30 70 2f } //01 00  ://alzheimerzamora.com/libraries/colorbutton/icons/hidpi/AYZRFTHkbj505hA3Aq0p/
		$a_01_2 = {3a 2f 2f 69 70 72 64 2e 6e 65 74 2e 70 68 74 65 6d 70 2e 63 6f 6d 2f 43 46 73 72 6a 6c 31 34 50 59 6b 43 65 42 64 61 2f } //00 00  ://iprd.net.phtemp.com/CFsrjl14PYkCeBda/
	condition:
		any of ($a_*)
 
}