
rule TrojanSpy_AndroidOS_SAgnt_Q_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.Q!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {47 65 74 41 6c 6c 43 6f 6e 74 61 63 74 73 } //1 GetAllContacts
		$a_01_1 = {5f 73 6d 73 6d 65 73 73 61 67 65 73 31 } //1 _smsmessages1
		$a_01_2 = {43 61 6c 6c 4c 6f 67 57 72 61 70 70 65 72 } //1 CallLogWrapper
		$a_01_3 = {2d 64 65 76 69 63 65 69 6e 66 6f 2e 74 78 74 } //1 -deviceinfo.txt
		$a_01_4 = {53 6d 73 57 72 61 70 70 65 72 } //1 SmsWrapper
		$a_01_5 = {73 63 72 65 65 6e 72 65 63 6f 72 64 } //1 screenrecord
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}