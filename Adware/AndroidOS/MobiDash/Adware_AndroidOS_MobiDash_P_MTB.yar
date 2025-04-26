
rule Adware_AndroidOS_MobiDash_P_MTB{
	meta:
		description = "Adware:AndroidOS/MobiDash.P!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6f 72 67 2f 63 6f 63 6f 73 32 64 78 2f 6a 61 6d 6d 73 2f 68 6f 68 6f 68 6f 2f 50 72 6f 76 69 64 65 72 } //1 org/cocos2dx/jamms/hohoho/Provider
		$a_01_1 = {68 6f 68 6f 68 6f 2e 64 62 } //1 hohoho.db
		$a_01_2 = {44 65 78 43 6c 61 73 73 4c 6f 61 64 65 72 } //1 DexClassLoader
		$a_01_3 = {4e 6f 74 69 66 69 63 61 74 69 6f 6e 4c 69 73 74 65 6e 65 72 } //1 NotificationListener
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}