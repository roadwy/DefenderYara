
rule Trojan_AndroidOS_Kotel_A_MTB{
	meta:
		description = "Trojan:AndroidOS/Kotel.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 70 68 6f 2f 6e 65 63 2f 73 67 2f 75 69 } //1 com/pho/nec/sg/ui
		$a_01_1 = {63 68 65 63 6b 50 68 6f 6e 65 4e 75 6d 45 78 69 73 74 41 6e 64 53 65 6e 64 4d 73 67 41 6e 64 4c 6f 63 6b } //1 checkPhoneNumExistAndSendMsgAndLock
		$a_01_2 = {67 65 74 4f 66 66 65 72 54 72 61 63 6b 55 72 6c } //1 getOfferTrackUrl
		$a_01_3 = {68 61 6e 64 6c 65 53 4d 53 53 65 6e 64 4f 4b } //1 handleSMSSendOK
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}