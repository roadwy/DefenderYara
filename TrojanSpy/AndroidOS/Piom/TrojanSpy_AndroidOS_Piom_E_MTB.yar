
rule TrojanSpy_AndroidOS_Piom_E_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Piom.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {4c 6f 63 61 6c 43 6f 6e 74 61 63 74 73 } //1 LocalContacts
		$a_00_1 = {4c 6f 63 61 6c 49 6d 61 67 65 } //1 LocalImage
		$a_00_2 = {4c 6f 63 61 6c 4d 65 73 73 61 67 65 } //1 LocalMessage
		$a_00_3 = {67 65 74 53 6d 73 62 6f 64 79 } //1 getSmsbody
		$a_00_4 = {67 65 74 50 68 6f 6e 65 4e 75 6d 62 65 72 } //1 getPhoneNumber
		$a_00_5 = {2f 61 70 69 2f 75 70 6c 6f 61 64 73 2f 61 70 69 } //1 /api/uploads/api
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}