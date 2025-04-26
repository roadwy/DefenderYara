
rule TrojanSpy_AndroidOS_SmsThief_CA_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsThief.CA!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2e 74 77 75 2e 69 6e 66 6f } //2 com.twu.info
		$a_00_1 = {53 6d 73 4f 62 73 65 72 76 65 72 } //1 SmsObserver
		$a_00_2 = {67 65 74 41 6c 6c 43 6f 6e 74 61 63 74 73 } //1 getAllContacts
		$a_00_3 = {67 65 74 53 6d 73 49 6e 50 68 6f 6e 65 } //1 getSmsInPhone
		$a_00_4 = {43 73 69 6e 66 6f } //1 Csinfo
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}