
rule TrojanSpy_AndroidOS_Mobinauten_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Mobinauten.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {66 69 6e 64 41 6e 64 53 65 6e 64 4c 6f 63 61 74 69 6f 6e } //1 findAndSendLocation
		$a_00_1 = {53 4d 53 53 50 59 } //1 SMSSPY
		$a_00_2 = {53 4d 53 5f 52 45 43 45 49 56 45 44 } //1 SMS_RECEIVED
		$a_00_3 = {6f 6e 53 74 61 72 74 43 6f 6d 6d 61 6e 64 } //1 onStartCommand
		$a_00_4 = {63 6f 6d 2f 64 65 2f 6d 6f 62 69 6e 61 75 74 65 6e 2f 73 6d 73 73 70 79 } //1 com/de/mobinauten/smsspy
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}