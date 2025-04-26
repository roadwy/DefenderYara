
rule Trojan_AndroidOS_SmsThief_P_MTB{
	meta:
		description = "Trojan:AndroidOS/SmsThief.P!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_03_0 = {4c 63 6f 6d 2f 64 68 72 75 76 2f 73 6d 73 72 65 63 65 76 69 65 72 ?? ?? 4d 61 69 6e 41 63 74 69 76 69 74 79 } //5
		$a_01_1 = {61 73 6b 61 67 61 69 6e } //1 askagain
		$a_01_2 = {67 65 74 44 69 73 70 6c 61 79 4d 65 73 73 61 67 65 42 6f 64 79 } //1 getDisplayMessageBody
		$a_01_3 = {73 65 6e 64 54 65 78 74 4d 65 73 73 61 67 65 } //1 sendTextMessage
		$a_01_4 = {4c 63 6f 6d 2f 62 69 6e 67 2f 63 68 61 74 74 69 6e 67 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 } //5 Lcom/bing/chatting/MainActivity
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*5) >=8
 
}