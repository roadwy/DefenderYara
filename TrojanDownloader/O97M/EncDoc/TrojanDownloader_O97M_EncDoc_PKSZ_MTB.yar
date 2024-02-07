
rule TrojanDownloader_O97M_EncDoc_PKSZ_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PKSZ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {63 6f 6c 6c 61 62 73 6f 6c 75 74 69 6f 6e 73 2e 63 6f 2e 7a 61 2f 6c 69 62 72 61 72 69 65 73 2f 71 6e 38 4c 4c 51 36 36 4b 2f } //01 00  collabsolutions.co.za/libraries/qn8LLQ66K/
		$a_01_1 = {63 6f 6d 65 63 65 62 65 6d 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 57 76 43 64 30 4f 66 5a 44 2f } //01 00  comecebem.com/wp-admin/WvCd0OfZD/
		$a_01_2 = {63 6f 6e 67 74 79 63 61 6d 76 69 6e 68 2e 63 6f 6d 2f 70 6c 75 67 69 6e 73 2f 72 77 50 52 57 61 7a 4e 6b 47 7a 67 2f } //01 00  congtycamvinh.com/plugins/rwPRWazNkGzg/
		$a_01_3 = {64 6f 74 63 6f 6d 70 61 6e 79 2e 63 6f 6d 2e 62 72 2f 61 75 74 6f 75 70 64 61 74 65 2f 57 56 7a 72 41 52 53 75 37 34 4e 74 53 68 36 31 75 46 2f } //00 00  dotcompany.com.br/autoupdate/WVzrARSu74NtSh61uF/
	condition:
		any of ($a_*)
 
}