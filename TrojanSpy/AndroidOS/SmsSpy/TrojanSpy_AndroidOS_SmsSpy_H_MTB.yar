
rule TrojanSpy_AndroidOS_SmsSpy_H_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsSpy.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 61 70 69 2f 75 70 6c 6f 61 64 73 2f 70 6f 73 74 6d 61 70 } //01 00  /api/uploads/postmap
		$a_00_1 = {67 65 74 53 6d 73 49 6e 50 68 6f 6e 65 20 68 61 73 20 65 78 65 63 75 74 65 64 } //01 00  getSmsInPhone has executed
		$a_00_2 = {67 65 74 41 6c 6c 43 6f 6e 74 61 63 74 73 } //01 00  getAllContacts
		$a_00_3 = {53 4d 53 5f 55 52 49 5f 41 4c 4c } //01 00  SMS_URI_ALL
		$a_00_4 = {75 70 6c 6f 61 64 47 73 } //01 00  uploadGs
		$a_00_5 = {2f 61 70 69 2f 75 70 6c 6f 61 64 73 2f 70 68 6f 74 6f } //00 00  /api/uploads/photo
	condition:
		any of ($a_*)
 
}