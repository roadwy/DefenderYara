
rule TrojanSpy_AndroidOS_SpyAgnt_I_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SpyAgnt.I!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {2f 61 70 69 2f 75 70 6c 6f 61 64 73 2f 61 70 69 } //1 /api/uploads/api
		$a_00_1 = {75 70 6c 6f 61 64 43 61 6c 6c 4c 6f 67 } //1 uploadCallLog
		$a_00_2 = {75 70 6c 6f 61 64 4d 65 73 73 61 67 65 73 } //1 uploadMessages
		$a_00_3 = {75 70 6c 6f 61 64 43 6f 6e 74 61 63 74 73 } //1 uploadContacts
		$a_00_4 = {75 70 6c 6f 61 64 49 6d 61 67 65 73 } //1 uploadImages
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}