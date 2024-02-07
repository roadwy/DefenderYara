
rule TrojanDownloader_O97M_Emotet_KAAR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.KAAR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 7a 6b 74 65 63 6f 76 6e 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 78 78 66 6e 59 59 34 7a 77 4f 70 46 4f 67 75 33 67 31 74 2f } //01 00  ://zktecovn.com/wp-admin/xxfnYY4zwOpFOgu3g1t/
		$a_01_1 = {3a 2f 2f 7a 61 63 68 61 72 79 77 79 74 68 65 2e 63 6f 6d 2f 70 62 5f 69 6e 64 65 78 5f 62 61 6b 2f 53 6b 45 47 42 32 63 2f } //01 00  ://zacharywythe.com/pb_index_bak/SkEGB2c/
		$a_01_2 = {3a 2f 2f 7a 6f 6e 61 69 6e 66 6f 72 6d 61 74 69 63 61 2e 65 73 2f 61 73 70 6e 65 74 5f 63 6c 69 65 6e 74 2f 70 56 63 70 70 67 69 30 30 44 6b 2f } //01 00  ://zonainformatica.es/aspnet_client/pVcppgi00Dk/
		$a_01_3 = {3a 2f 2f 7a 73 70 77 6f 6c 61 77 69 61 7a 6f 77 61 2e 70 6c 2f 69 6d 61 67 65 73 2f 6d 45 32 5a 6d 38 52 4b 70 61 4c 6b 34 30 73 6b 2f } //00 00  ://zspwolawiazowa.pl/images/mE2Zm8RKpaLk40sk/
	condition:
		any of ($a_*)
 
}