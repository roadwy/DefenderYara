
rule Trojan_AndroidOS_SpyBanker_AV{
	meta:
		description = "Trojan:AndroidOS/SpyBanker.AV,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {6d 61 6b 65 52 65 71 75 65 73 74 46 6f 72 47 65 74 74 69 6e 67 44 61 74 61 46 72 6f 6d 53 65 72 76 65 72 } //2 makeRequestForGettingDataFromServer
		$a_01_1 = {45 58 45 43 55 54 49 4f 4e 5f 54 45 4c 45 50 48 4f 4e 59 5f 52 41 54 5f 43 4f 4d 4d 41 4e 44 } //2 EXECUTION_TELEPHONY_RAT_COMMAND
		$a_01_2 = {6d 61 6b 65 47 65 74 74 69 6e 67 42 61 6c 61 6e 63 65 52 65 71 75 65 73 74 } //2 makeGettingBalanceRequest
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}