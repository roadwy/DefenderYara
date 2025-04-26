
rule TrojanSpy_AndroidOS_FakeSupport_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/FakeSupport.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 65 78 61 6d 70 6c 65 2f 63 6f 6d 70 6c 61 69 6e 74 72 65 67 69 73 74 65 72 73 2f 43 6f 6d 70 6c 61 69 6e 44 61 74 61 } //1 Lcom/example/complaintregisters/ComplainData
		$a_00_1 = {67 65 74 44 65 62 69 74 43 61 72 64 4e 75 6d 62 65 72 } //1 getDebitCardNumber
		$a_00_2 = {67 65 74 41 74 6d 50 69 6e } //1 getAtmPin
		$a_00_3 = {67 65 74 54 72 61 6e 73 61 63 74 69 6f 6e 50 61 73 73 77 6f 72 64 } //1 getTransactionPassword
		$a_00_4 = {77 77 77 2e 63 6f 6d 70 6c 61 69 6e 74 73 72 65 67 69 73 74 65 72 71 75 65 72 79 2e 63 6f 6d } //1 www.complaintsregisterquery.com
		$a_00_5 = {67 65 74 41 6c 6c 53 6d 73 } //1 getAllSms
		$a_00_6 = {67 65 74 41 63 63 6f 75 6e 74 4e 75 6d 62 65 72 } //1 getAccountNumber
		$a_00_7 = {2f 6d 73 67 73 74 6f 72 65 3f 74 61 73 6b 3d 73 61 76 65 6d 73 67 } //1 /msgstore?task=savemsg
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=7
 
}