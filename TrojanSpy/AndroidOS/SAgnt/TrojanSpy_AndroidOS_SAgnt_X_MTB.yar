
rule TrojanSpy_AndroidOS_SAgnt_X_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.X!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 64 65 6d 6f 2f 70 72 6f 6d 65 74 68 65 75 73 2f 61 70 69 2f 41 70 69 4d 61 6e 61 67 65 72 } //1 com/demo/prometheus/api/ApiManager
		$a_01_1 = {63 6f 6e 74 61 63 74 73 2e 64 62 } //1 contacts.db
		$a_01_2 = {6b 69 6c 6c 50 72 6f 63 65 73 73 } //1 killProcess
		$a_01_3 = {75 70 6c 6f 61 64 43 61 6c 6c 52 65 63 6f 72 64 } //1 uploadCallRecord
		$a_01_4 = {61 6e 64 72 6f 69 64 2e 69 6e 74 65 6e 74 2e 61 63 74 69 6f 6e 2e 55 70 6c 6f 61 64 2e 43 61 6c 6c 2e 52 65 63 6f 72 64 } //1 android.intent.action.Upload.Call.Record
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}