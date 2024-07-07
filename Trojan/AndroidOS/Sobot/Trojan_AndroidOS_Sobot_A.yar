
rule Trojan_AndroidOS_Sobot_A{
	meta:
		description = "Trojan:AndroidOS/Sobot.A,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 74 61 74 75 73 4d 65 73 61 6a } //1 statusMesaj
		$a_01_1 = {41 70 70 53 65 72 76 69 63 65 24 4c 6f 63 61 6c 55 73 65 72 49 6e 66 6f } //1 AppService$LocalUserInfo
		$a_01_2 = {74 69 6d 65 72 53 74 6f 70 52 65 66 72 65 73 68 69 6e 67 } //1 timerStopRefreshing
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}