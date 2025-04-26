
rule Trojan_AndroidOS_SpyBanker_D_MTB{
	meta:
		description = "Trojan:AndroidOS/SpyBanker.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 61 69 6c 52 65 63 65 69 76 65 72 } //1 DailReceiver
		$a_01_1 = {75 70 64 61 74 65 43 61 6c 6c 4c 6f 67 } //1 updateCallLog
		$a_01_2 = {50 68 6f 6e 65 53 74 61 74 52 65 63 65 69 76 65 72 } //1 PhoneStatReceiver
		$a_01_3 = {73 65 6e 64 43 61 6c 6c 49 6e 66 6f } //1 sendCallInfo
		$a_01_4 = {73 65 6e 64 55 73 65 72 49 6e 66 6f } //1 sendUserInfo
		$a_01_5 = {67 65 74 43 61 6c 6c 4e 75 6d 62 65 72 49 6e 66 6f } //1 getCallNumberInfo
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}