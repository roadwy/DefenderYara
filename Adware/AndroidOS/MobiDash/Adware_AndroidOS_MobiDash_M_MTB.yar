
rule Adware_AndroidOS_MobiDash_M_MTB{
	meta:
		description = "Adware:AndroidOS/MobiDash.M!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 61 6d 6f 73 6d 6f 62 69 6c 65 2f 72 6f 6f 74 63 68 65 63 6b 2f 52 6f 6f 74 43 68 65 63 6b 41 63 74 69 76 69 74 79 } //1 com/amosmobile/rootcheck/RootCheckActivity
		$a_01_1 = {73 68 61 72 65 4d 79 44 61 74 61 } //1 shareMyData
		$a_03_2 = {6d 61 69 6c 74 6f ?? 61 6d 6f 73 6d 6f 62 69 6c 65 35 35 40 67 6d 61 69 6c 2e 63 6f 6d } //1
		$a_01_3 = {4e 6f 74 69 66 69 63 61 74 69 6f 6e 4c 69 73 74 65 6e 65 72 } //1 NotificationListener
		$a_01_4 = {44 65 78 43 6c 61 73 73 4c 6f 61 64 65 72 } //1 DexClassLoader
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}