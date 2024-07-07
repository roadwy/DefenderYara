
rule Trojan_AndroidOS_SpyAgent_SG_MTB{
	meta:
		description = "Trojan:AndroidOS/SpyAgent.SG!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 69 6d 67 2e 74 66 71 30 2e 63 6e 3a 39 30 } //1 http://img.tfq0.cn:90
		$a_01_1 = {6d 79 54 65 6c } //1 myTel
		$a_01_2 = {6d 79 4d 73 67 73 } //1 myMsgs
		$a_01_3 = {6d 79 49 6e 66 6f } //1 myInfo
		$a_01_4 = {6d 79 4d 6f 64 65 6c } //1 myModel
		$a_01_5 = {6a 61 76 61 73 63 72 69 70 74 3a 6a 61 76 61 43 61 6c 6c 4a 73 28 29 } //1 javascript:javaCallJs()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}