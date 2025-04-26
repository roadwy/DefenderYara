
rule Adware_AndroidOS_MobiDash_L_MTB{
	meta:
		description = "Adware:AndroidOS/MobiDash.L!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 66 66 73 2f 73 75 70 65 72 68 65 72 6f 65 73 2f 6a 75 6e 69 6f 72 2f 50 72 6f 76 69 64 65 72 } //1 com/ffs/superheroes/junior/Provider
		$a_01_1 = {6a 75 6e 69 6f 72 2e 64 62 } //1 junior.db
		$a_01_2 = {6d 6b 64 69 72 43 68 65 63 6b 65 64 } //1 mkdirChecked
		$a_01_3 = {44 65 78 43 6c 61 73 73 4c 6f 61 64 65 72 } //1 DexClassLoader
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}