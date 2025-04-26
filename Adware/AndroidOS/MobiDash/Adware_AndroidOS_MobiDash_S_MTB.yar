
rule Adware_AndroidOS_MobiDash_S_MTB{
	meta:
		description = "Adware:AndroidOS/MobiDash.S!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 63 79 72 6f 73 65 68 64 6d 6f 76 69 65 2f 62 6f 78 6f 66 66 69 63 65 2f 50 72 6f 76 69 64 65 72 } //1 com/cyrosehdmovie/boxoffice/Provider
		$a_01_1 = {62 6f 78 6f 66 66 69 63 65 2e 64 62 } //1 boxoffice.db
		$a_01_2 = {44 65 78 43 6c 61 73 73 4c 6f 61 64 65 72 } //1 DexClassLoader
		$a_01_3 = {4e 6f 74 69 66 69 63 61 74 69 6f 6e 4c 69 73 74 65 6e 65 72 } //1 NotificationListener
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}