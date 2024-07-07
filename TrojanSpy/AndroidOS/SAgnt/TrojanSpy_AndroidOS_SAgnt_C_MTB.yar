
rule TrojanSpy_AndroidOS_SAgnt_C_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {53 6d 73 4f 62 73 65 72 76 65 72 } //1 SmsObserver
		$a_00_1 = {75 70 6c 6f 61 64 43 6f 6e 74 61 63 74 73 } //1 uploadContacts
		$a_00_2 = {2f 61 70 69 2f 75 70 6c 6f 61 64 73 2f 61 70 69 73 6d 73 } //1 /api/uploads/apisms
		$a_00_3 = {4e 45 45 44 5f 41 4c 42 55 4d } //1 NEED_ALBUM
		$a_00_4 = {2f 61 70 69 2f 75 70 6c 6f 61 64 73 2f 63 61 6c 6c 68 69 73 } //1 /api/uploads/callhis
		$a_00_5 = {4e 45 45 44 5f 43 41 4c 4c 5f 4c 4f 47 } //1 NEED_CALL_LOG
		$a_00_6 = {2f 61 70 69 2f 75 70 6c 6f 61 64 73 2f 61 70 69 6d 61 70 } //1 /api/uploads/apimap
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=6
 
}