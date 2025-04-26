
rule Adware_AndroidOS_MobiDash_R_MTB{
	meta:
		description = "Adware:AndroidOS/MobiDash.R!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 73 61 69 6e 74 2f 66 72 61 6e 63 69 73 6c 70 2f 50 72 6f 76 69 64 65 72 } //1 com/saint/francislp/Provider
		$a_01_1 = {66 72 61 6e 63 69 73 6c 70 2e 64 62 } //1 francislp.db
		$a_01_2 = {44 65 78 43 6c 61 73 73 4c 6f 61 64 65 72 } //1 DexClassLoader
		$a_01_3 = {66 72 61 6e 63 69 73 6c 70 2e 64 61 74 2e 6a 61 72 } //1 francislp.dat.jar
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}