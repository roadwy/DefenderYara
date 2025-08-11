
rule TrojanSpy_AndroidOS_SAgnt_BD_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.BD!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {4c 63 6e 2f 72 65 61 6c 73 68 65 6c 6c 2f 43 6f 72 65 53 65 72 76 69 63 65 } //1 Lcn/realshell/CoreService
		$a_01_1 = {47 48 4f 53 54 53 48 45 4c 4c 5f 53 45 4e 44 5f 53 4d 53 } //1 GHOSTSHELL_SEND_SMS
		$a_01_2 = {68 6f 6f 6b 50 75 62 6c 69 73 68 53 65 72 76 69 63 65 } //1 hookPublishService
		$a_01_3 = {63 6e 2e 72 65 61 6c 73 68 65 6c 6c 2e 43 68 61 6e 6e 65 6c 44 61 74 61 } //1 cn.realshell.ChannelData
		$a_01_4 = {52 45 41 4c 53 48 45 4c 4c 5f 50 4c 55 47 49 4e 53 } //1 REALSHELL_PLUGINS
		$a_01_5 = {4c 63 6f 6d 2f 79 73 2f 73 65 72 76 69 63 65 2f 57 6f 72 6b 53 74 61 72 74 52 65 63 65 69 76 65 72 } //1 Lcom/ys/service/WorkStartReceiver
		$a_01_6 = {4d 45 53 53 41 47 45 5f 44 4f 57 4e 4c 4f 41 44 5f 50 4c 55 47 49 4e 53 } //1 MESSAGE_DOWNLOAD_PLUGINS
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}