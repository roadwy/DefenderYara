
rule Trojan_AndroidOS_Rewardsteal_O{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.O,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {67 65 6e 65 72 61 74 65 41 6c 70 68 61 6e 75 6d 65 72 69 63 57 6f 72 64 } //2 generateAlphanumericWord
		$a_01_1 = {69 6e 73 65 72 74 4d 73 67 64 61 74 61 3a 20 6d 61 73 73 61 67 65 } //2 insertMsgdata: massage
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}