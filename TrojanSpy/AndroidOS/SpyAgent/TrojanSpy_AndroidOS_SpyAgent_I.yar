
rule TrojanSpy_AndroidOS_SpyAgent_I{
	meta:
		description = "TrojanSpy:AndroidOS/SpyAgent.I,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {67 65 74 53 69 6d 43 6f 6e 74 61 63 74 49 6e 66 6f 4c 69 73 74 } //1 getSimContactInfoList
		$a_00_1 = {43 61 6c 6c 52 65 63 6f 72 64 55 74 69 6c } //1 CallRecordUtil
		$a_00_2 = {67 70 73 5f 61 64 64 72 65 73 73 5f 63 69 74 79 } //1 gps_address_city
		$a_00_3 = {67 65 74 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 4e 75 6d 62 65 72 } //1 getDownloadFileNumber
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}