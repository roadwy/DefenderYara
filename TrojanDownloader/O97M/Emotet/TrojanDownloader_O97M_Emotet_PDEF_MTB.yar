
rule TrojanDownloader_O97M_Emotet_PDEF_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.PDEF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_01_0 = {3a 2f 2f 77 77 77 2e 64 6e 61 68 65 61 6c 74 68 2e 67 72 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 51 6b 6b 4b 4d 61 4c 77 79 34 6a 55 52 68 36 46 44 2f } //1 ://www.dnahealth.gr/wp-content/QkkKMaLwy4jURh6FD/
		$a_01_1 = {3a 2f 2f 77 77 77 2e 63 61 6d 70 75 73 63 6f 6e 69 6e 64 69 67 69 74 61 6c 2e 6f 72 67 2f 6d 6f 6f 64 6c 65 5f 6f 6c 64 2f 39 67 69 67 6c 48 72 67 32 74 2f } //1 ://www.campusconindigital.org/moodle_old/9giglHrg2t/
		$a_01_2 = {3a 2f 2f 77 77 77 2e 65 61 70 72 6f 2e 69 6e 2f 77 70 2d 61 64 6d 69 6e 2f 73 66 32 4d 70 70 50 57 33 30 63 4b 61 57 65 6b 6f 2f } //1 ://www.eapro.in/wp-admin/sf2MppPW30cKaWeko/
		$a_01_3 = {3a 2f 2f 77 77 77 2e 64 69 67 69 74 61 6c 6b 68 75 6c 6e 61 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 4c 32 7a 32 65 2f } //1 ://www.digitalkhulna.com/wp-admin/L2z2e/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=1
 
}