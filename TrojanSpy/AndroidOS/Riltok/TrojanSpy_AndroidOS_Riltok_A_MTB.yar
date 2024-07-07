
rule TrojanSpy_AndroidOS_Riltok_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Riltok.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {72 65 61 6c 74 61 6c 6b 2d 6a 6e 69 } //1 realtalk-jni
		$a_00_1 = {52 45 41 4c 54 41 4c 4b 20 52 45 51 55 45 53 54 } //1 REALTALK REQUEST
		$a_00_2 = {6d 6f 76 65 5f 73 6d 73 5f 63 6c 69 65 6e 74 } //1 move_sms_client
		$a_00_3 = {73 65 74 53 65 72 76 65 72 47 61 74 65 } //1 setServerGate
		$a_00_4 = {53 65 74 4a 61 76 61 53 63 72 69 70 74 45 6e 61 62 6c 65 64 } //1 SetJavaScriptEnabled
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}