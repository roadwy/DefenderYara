
rule TrojanSpy_AndroidOS_Gepew_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Gepew.A.MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {4b 52 5f 4e 48 42 61 6e 6b 2e 61 70 6b } //1 KR_NHBank.apk
		$a_00_1 = {61 70 70 2e 64 77 6f 6e 6c 6f 61 64 2e 63 6f 6d 70 6c 61 74 65 } //1 app.dwonload.complate
		$a_00_2 = {61 75 74 6f 43 68 61 6e 67 65 41 70 6b } //1 autoChangeApk
		$a_00_3 = {53 4d 53 5f 53 45 4e 44 5f 41 43 54 49 4f 49 4e } //1 SMS_SEND_ACTIOIN
		$a_00_4 = {6b 6f 72 65 61 2e 6b 72 5f 6e 68 62 61 6e 6b } //1 korea.kr_nhbank
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}