
rule TrojanSpy_AndroidOS_Fakecalls_C_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Fakecalls.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 4c 49 43 4b 5f 48 49 47 48 5f 50 45 52 4d 49 53 53 49 4f 4e 5f 54 49 4d 45 53 } //1 CLICK_HIGH_PERMISSION_TIMES
		$a_01_1 = {49 53 5f 55 50 4c 4f 41 44 49 4e 47 5f 43 41 4c 4c 5f 4c 4f 47 } //1 IS_UPLOADING_CALL_LOG
		$a_01_2 = {52 45 51 55 45 53 54 5f 55 50 4c 4f 41 44 5f 45 58 54 52 41 5f 49 4e 46 4f } //1 REQUEST_UPLOAD_EXTRA_INFO
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}