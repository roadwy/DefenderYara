
rule TrojanSpy_AndroidOS_SmForw_H_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmForw.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {43 6f 6e 74 61 63 74 49 6e 66 6f } //1 ContactInfo
		$a_01_1 = {43 48 45 43 4b 5f 4f 55 54 47 4f 49 4e 47 5f 53 4d 53 } //1 CHECK_OUTGOING_SMS
		$a_01_2 = {63 6f 6e 74 61 63 74 2e 74 78 74 } //1 contact.txt
		$a_01_3 = {4d 6f 6e 69 74 6f 72 53 4d 53 } //1 MonitorSMS
		$a_01_4 = {4f 75 74 67 6f 69 6e 67 53 6d 73 4c 6f 67 67 65 72 } //1 OutgoingSmsLogger
		$a_01_5 = {4c 63 6f 6d 2f 61 6e 64 72 6f 69 64 2f 73 65 63 72 65 74 74 61 6c 6b } //1 Lcom/android/secrettalk
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}