
rule Trojan_AndroidOS_Lijo_B_MTB{
	meta:
		description = "Trojan:AndroidOS/Lijo.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 08 00 00 "
		
	strings :
		$a_00_0 = {53 4d 53 47 72 61 62 62 65 72 } //1 SMSGrabber
		$a_00_1 = {73 78 2e 6a 6f 6c 6c 79 2e 70 61 72 74 6e 65 72 } //1 sx.jolly.partner
		$a_00_2 = {53 41 56 45 53 4d 53 4c 4f 47 53 } //1 SAVESMSLOGS
		$a_00_3 = {4d 54 42 4f 54 5f 4e 55 4d 42 45 52 } //1 MTBOT_NUMBER
		$a_00_4 = {53 65 6e 64 4c 6f 67 73 } //1 SendLogs
		$a_00_5 = {73 65 6e 64 53 65 6c 66 4e 75 6d 62 65 72 54 6f 4d 54 42 6f 74 } //1 sendSelfNumberToMTBot
		$a_00_6 = {70 61 72 74 6e 65 72 73 6c 61 62 2e 63 6f 6d 63 6c 6f 75 64 2f 73 61 76 65 6c 6f 67 2f } //1 partnerslab.comcloud/savelog/
		$a_00_7 = {68 74 74 70 3a 2f 2f 70 61 72 74 6e 65 72 73 6c 61 62 2e 63 6f 6d } //1 http://partnerslab.com
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=6
 
}