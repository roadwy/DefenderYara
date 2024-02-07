
rule TrojanDownloader_O97M_Emotet_AJPD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.AJPD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 61 69 72 6c 69 66 74 6c 69 6d 6f 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 77 7a 5a 33 52 49 73 49 74 78 5a 73 75 37 37 4d 46 78 73 2f } //01 00  ://airliftlimo.com/wp-admin/wzZ3RIsItxZsu77MFxs/
		$a_01_1 = {3a 2f 2f 64 65 6d 6f 2d 72 65 2d 75 73 61 62 6c 65 73 2e 69 6e 65 72 74 69 61 73 6f 66 74 2e 6e 65 74 2f 63 67 69 2d 62 69 6e 2f 41 52 34 6e 59 4e 64 39 78 70 6e 2f } //01 00  ://demo-re-usables.inertiasoft.net/cgi-bin/AR4nYNd9xpn/
		$a_01_2 = {3a 2f 2f 6a 75 73 74 70 6c 61 79 2e 61 73 69 61 2f 67 6f 6f 67 6c 65 2f 6f 43 62 79 50 77 42 38 42 2f } //01 00  ://justplay.asia/google/oCbyPwB8B/
		$a_01_3 = {3a 2f 2f 61 76 65 6e 75 65 62 72 61 73 69 6c 2e 63 6f 6d 2f 5f 69 6d 67 2f 35 4b 41 71 51 2f } //00 00  ://avenuebrasil.com/_img/5KAqQ/
	condition:
		any of ($a_*)
 
}