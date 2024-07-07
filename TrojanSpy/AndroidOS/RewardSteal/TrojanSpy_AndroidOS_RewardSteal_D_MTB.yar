
rule TrojanSpy_AndroidOS_RewardSteal_D_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/RewardSteal.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 75 62 6d 69 74 43 6f 6e 74 61 63 74 4d 73 67 44 61 74 61 } //1 submitContactMsgData
		$a_01_1 = {67 65 74 5f 6d 73 67 5f 61 6e 64 5f 63 6f 6e 74 61 63 74 } //1 get_msg_and_contact
		$a_01_2 = {4c 63 6f 6d 2f 61 70 70 2f 62 6f 6e 75 73 72 65 77 61 72 64 } //1 Lcom/app/bonusreward
		$a_01_3 = {50 72 65 73 65 6e 74 65 72 53 4d 53 } //1 PresenterSMS
		$a_01_4 = {73 75 62 6d 69 74 46 6f 72 6d 44 61 74 61 } //1 submitFormData
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}