
rule Trojan_AndroidOS_Rewardsteal_AX{
	meta:
		description = "Trojan:AndroidOS/Rewardsteal.AX,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 74 61 72 74 53 6d 73 46 6f 72 77 61 72 64 69 6e 67 53 65 72 76 69 63 65 } //2 startSmsForwardingService
		$a_01_1 = {61 70 70 6b 6b 66 66 72 72 64 64 2f 53 6d 73 52 65 70 6f 73 69 74 6f 72 79 } //2 appkkffrrdd/SmsRepository
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}