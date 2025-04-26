
rule TrojanSpy_AndroidOS_GigaBudRAT_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/GigaBudRAT.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {78 2f 75 73 65 72 2d 62 61 6e 6b 2d 70 77 64 } //1 x/user-bank-pwd
		$a_01_1 = {62 61 6e 6b 49 6d 67 } //1 bankImg
		$a_01_2 = {53 65 6e 64 4d 73 67 49 6e 66 6f } //1 SendMsgInfo
		$a_01_3 = {42 61 6e 6b 43 61 72 64 49 6e 66 6f } //1 BankCardInfo
		$a_01_4 = {6f 6e 52 65 63 65 69 76 65 72 43 6f 6d 6d 65 6e 64 61 63 74 69 6f 6e } //1 onReceiverCommendaction
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}