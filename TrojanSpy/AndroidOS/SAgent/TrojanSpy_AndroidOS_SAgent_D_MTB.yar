
rule TrojanSpy_AndroidOS_SAgent_D_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgent.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_03_0 = {4c 63 6f 6d 2f 62 72 6f 77 73 65 72 2f 77 65 62 [0-04] 2f 53 6d 73 52 65 63 65 69 76 65 72 } //1
		$a_03_1 = {2f 61 70 69 2f 73 6d 73 2d 74 65 73 74 2f [0-10] 2e 70 68 70 } //1
		$a_01_2 = {73 65 6e 64 65 72 70 68 6f 6e 65 34 } //1 senderphone4
		$a_01_3 = {64 65 76 69 63 65 6d 6f 64 65 6c 34 } //1 devicemodel4
		$a_01_4 = {73 6f 75 72 63 65 7a 34 } //1 sourcez4
		$a_01_5 = {67 65 74 44 69 73 70 6c 61 79 4f 72 69 67 69 6e 61 74 69 6e 67 41 64 64 72 65 73 73 } //1 getDisplayOriginatingAddress
		$a_01_6 = {65 78 74 72 61 5f 73 6d 73 5f 6d 65 73 73 61 67 65 } //1 extra_sms_message
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}