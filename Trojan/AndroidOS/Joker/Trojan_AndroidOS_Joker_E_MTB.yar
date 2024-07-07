
rule Trojan_AndroidOS_Joker_E_MTB{
	meta:
		description = "Trojan:AndroidOS/Joker.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {2e 61 6c 69 79 75 6e 63 73 2e 63 6f 6d 2f } //2 .aliyuncs.com/
		$a_01_1 = {72 71 75 65 73 74 50 68 6f 6e 65 50 65 72 6d 69 73 73 69 6f 6e } //2 rquestPhonePermission
		$a_00_2 = {63 6f 6d 2e 61 6e 74 75 6d 65 2e 43 61 6e 74 69 6e } //2 com.antume.Cantin
		$a_01_3 = {73 74 61 72 74 53 44 4b } //1 startSDK
		$a_01_4 = {63 61 6e 63 65 6c 41 6c 6c 4e 6f 74 69 66 69 63 61 74 69 6f 6e 73 } //1 cancelAllNotifications
		$a_01_5 = {67 65 74 44 65 66 61 75 6c 74 53 6d 73 50 61 63 6b 61 67 65 } //1 getDefaultSmsPackage
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_00_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}