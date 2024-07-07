
rule TrojanSpy_AndroidOS_SpyAgnt_M_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SpyAgnt.M!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_00_0 = {2f 61 70 69 2f 75 70 6c 6f 61 64 73 2f 61 70 69 } //1 /api/uploads/api
		$a_00_1 = {61 70 69 2f 75 70 6c 6f 61 64 73 2f 63 61 6c 6c 68 69 73 } //1 api/uploads/callhis
		$a_00_2 = {67 65 74 63 6c 69 70 64 61 74 61 } //1 getclipdata
		$a_00_3 = {61 70 69 2f 75 70 6c 6f 61 64 73 2f 61 70 69 73 6d 73 } //1 api/uploads/apisms
		$a_00_4 = {67 65 74 50 68 6f 6e 65 } //1 getPhone
		$a_00_5 = {67 65 74 6c 61 73 74 6b 6e 6f 77 6e 6c 6f 63 61 74 69 6f 6e } //1 getlastknownlocation
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=4
 
}