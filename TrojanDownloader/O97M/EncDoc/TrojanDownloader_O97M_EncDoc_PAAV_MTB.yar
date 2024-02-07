
rule TrojanDownloader_O97M_EncDoc_PAAV_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PAAV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 61 70 65 72 73 6f 6e 65 6d 62 63 65 72 74 61 69 6e 6c 79 64 69 72 65 63 74 6f 72 73 68 6f 75 6c 64 73 74 75 64 65 6e 74 61 74 } //02 00  capersonembcertainlydirectorshouldstudentat
		$a_01_1 = {65 63 68 6f 63 68 65 63 6b 69 6e 67 6e 6f 77 70 72 69 6e 74 31 70 6f 77 65 72 73 68 65 6c 6c 77 68 69 64 73 6c 65 65 70 73 65 33 33 73 74 61 72 74 62 69 74 73 74 72 61 6e 73 66 65 72 73 6f 75 68 74 74 70 73 72 65 61 6c 77 61 6c 6c 78 32 34 68 72 63 6f 6d 73 65 63 76 69 6d 76 70 6e 65 78 65 } //00 00  echocheckingnowprint1powershellwhidsleepse33startbitstransfersouhttpsrealwallx24hrcomsecvimvpnexe
	condition:
		any of ($a_*)
 
}