
rule Trojan_AndroidOS_FakeInst_F_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeInst.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {67 65 74 4d 65 73 73 61 67 65 4c 69 73 74 42 79 4c 6f 63 } //1 getMessageListByLoc
		$a_00_1 = {53 61 76 65 4d 73 67 54 6f 46 69 6c 65 } //1 SaveMsgToFile
		$a_00_2 = {67 65 74 4d 65 73 73 61 67 65 4c 69 73 74 } //1 getMessageList
		$a_00_3 = {63 61 6e 63 65 6c 43 75 72 72 4e 6f 74 69 66 } //1 cancelCurrNotif
		$a_00_4 = {67 6f 50 6c 69 50 61 79 41 63 74 69 76 69 74 79 42 79 55 72 6c } //1 goPliPayActivityByUrl
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}