
rule TrojanDownloader_BAT_MSILLoader_CSWF_MTB{
	meta:
		description = "TrojanDownloader:BAT/MSILLoader.CSWF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 03 00 00 05 00 "
		
	strings :
		$a_01_0 = {03 06 91 15 2d 15 26 03 06 03 07 91 9c 03 07 08 9c 06 17 58 0a 07 17 59 0b 2b 03 0c 2b e9 06 07 32 } //01 00 
		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 73 00 65 00 72 00 76 00 65 00 72 00 2e 00 64 00 75 00 63 00 6b 00 64 00 6e 00 73 00 2e 00 6f 00 72 00 67 00 2f 00 53 00 79 00 73 00 74 00 65 00 6d 00 45 00 6e 00 76 00 2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 73 00 } //01 00  http://downloadserver.duckdns.org/SystemEnv/uploads
		$a_01_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 6d 00 61 00 6c 00 6f 00 79 00 6d 00 65 00 7a 00 2e 00 62 00 65 00 67 00 65 00 74 00 2e 00 74 00 65 00 63 00 68 00 2f 00 70 00 61 00 6e 00 65 00 6c 00 2f 00 75 00 70 00 6c 00 6f 00 61 00 64 00 73 00 2f 00 } //00 00  http://maloymez.beget.tech/panel/uploads/
	condition:
		any of ($a_*)
 
}