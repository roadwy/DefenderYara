
rule TrojanSpy_AndroidOS_FakeBank_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/FakeBank.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0c 00 0c 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 61 70 70 2f 6d 61 6e 61 67 65 72 2f 61 78 69 73 2f 72 65 73 74 61 70 69 } //10 com/app/manager/axis/restapi
		$a_01_1 = {63 6f 6d 2f 61 70 70 2f 6d 61 6e 61 67 65 72 2f 68 64 66 63 2f 72 65 73 74 61 70 69 } //10 com/app/manager/hdfc/restapi
		$a_01_2 = {63 6f 6d 2f 61 70 70 2f 6d 61 6e 61 67 65 72 2f 72 62 6c 2f 72 65 73 74 61 70 69 } //10 com/app/manager/rbl/restapi
		$a_01_3 = {73 61 76 65 70 65 72 73 6f 6e 61 6c 64 65 74 61 69 6c 73 5f 73 74 65 70 66 69 72 73 74 } //1 savepersonaldetails_stepfirst
		$a_01_4 = {63 61 72 64 5f 6e 75 6d 62 65 72 } //1 card_number
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=12
 
}