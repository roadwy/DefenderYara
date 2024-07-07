
rule TrojanSpy_AndroidOS_SmsThief_T_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.T!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_02_0 = {4c 63 6f 6d 2f 68 65 6c 70 64 65 76 2f 90 02 08 71 75 69 63 6b 73 75 70 70 6f 72 74 2f 72 65 63 65 69 76 65 72 2f 53 6d 73 52 65 63 65 69 76 65 72 3b 90 00 } //1
		$a_00_1 = {72 65 71 75 65 73 74 53 6d 73 50 65 72 6d 69 73 73 69 6f 6e } //1 requestSmsPermission
		$a_00_2 = {68 69 64 65 41 70 70 } //1 hideApp
		$a_00_3 = {66 65 74 63 68 4c 6f 67 6f } //1 fetchLogo
		$a_00_4 = {61 75 74 6f 4c 61 75 6e 63 68 56 69 76 6f } //1 autoLaunchVivo
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}