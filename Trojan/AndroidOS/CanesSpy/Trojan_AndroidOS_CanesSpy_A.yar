
rule Trojan_AndroidOS_CanesSpy_A{
	meta:
		description = "Trojan:AndroidOS/CanesSpy.A,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 05 00 00 "
		
	strings :
		$a_00_0 = {53 55 42 53 43 52 49 50 45 52 5f 49 44 5f 53 4c 4f 54 5f 31 } //1 SUBSCRIPER_ID_SLOT_1
		$a_00_1 = {44 45 56 49 43 45 5f 55 4e 49 51 55 45 5f 49 44 53 68 61 72 65 64 } //1 DEVICE_UNIQUE_IDShared
		$a_00_2 = {55 50 4c 4f 41 44 5f 46 49 4c 45 53 5f 4e 41 4d 45 53 5f 49 4e 5f 44 45 56 49 43 45 } //1 UPLOAD_FILES_NAMES_IN_DEVICE
		$a_00_3 = {53 54 4f 50 5f 55 50 4c 4f 41 44 5f 46 49 4c 45 5f 57 41 53 5f 55 50 4c 4f 41 44 45 44 } //1 STOP_UPLOAD_FILE_WAS_UPLOADED
		$a_00_4 = {4c 63 6f 6d 2f 67 6f 6f 67 6c 65 2f 61 6e 64 72 6f 69 64 2f 73 65 61 72 63 68 2f 76 61 6c 69 64 61 74 65 2f } //1 Lcom/google/android/search/validate/
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=2
 
}