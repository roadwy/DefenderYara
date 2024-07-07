
rule Backdoor_AndroidOS_Levida_B_MTB{
	meta:
		description = "Backdoor:AndroidOS/Levida.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4c 63 6f 6d 2f 73 6c 2f 6c 6f 61 64 65 72 } //1 Lcom/sl/loader
		$a_01_1 = {63 6f 6d 2e 73 6c 2e 75 70 64 61 74 65 2e 53 65 6c 66 55 70 64 61 74 65 } //1 com.sl.update.SelfUpdate
		$a_01_2 = {63 6f 6d 2e 73 6c 2e 61 64 6d 69 6e 2e 53 4c 44 65 76 69 63 65 41 64 6d 69 6e 52 65 63 65 69 76 65 72 } //1 com.sl.admin.SLDeviceAdminReceiver
		$a_01_3 = {61 64 73 2e 53 6c 69 63 6b 41 64 41 63 74 69 76 69 74 79 } //1 ads.SlickAdActivity
		$a_01_4 = {67 65 74 43 6c 61 73 73 4c 6f 61 64 65 72 } //1 getClassLoader
		$a_01_5 = {53 4c 53 44 4b 2e 61 70 6b } //1 SLSDK.apk
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}