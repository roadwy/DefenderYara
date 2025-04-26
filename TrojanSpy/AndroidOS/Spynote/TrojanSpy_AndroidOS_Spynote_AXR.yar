
rule TrojanSpy_AndroidOS_Spynote_AXR{
	meta:
		description = "TrojanSpy:AndroidOS/Spynote.AXR,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 70 6c 61 73 68 2e 6d 73 69 63 61 70 70 2e 6e 65 74 61 6c 66 61 2e 52 45 43 4f 52 44 } //1 splash.msicapp.netalfa.RECORD
		$a_01_1 = {75 73 72 67 6d 61 69 6c } //1 usrgmail
		$a_01_2 = {41 63 74 69 76 53 65 6e 64 } //1 ActivSend
		$a_01_3 = {47 65 74 4c 6f 67 73 } //1 GetLogs
		$a_01_4 = {53 74 6f 72 61 67 50 65 72 6d 69 73 73 69 6f 6e 73 } //1 StoragPermissions
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}