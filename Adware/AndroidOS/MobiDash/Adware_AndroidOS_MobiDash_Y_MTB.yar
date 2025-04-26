
rule Adware_AndroidOS_MobiDash_Y_MTB{
	meta:
		description = "Adware:AndroidOS/MobiDash.Y!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 70 72 69 6f 72 69 74 79 68 65 61 6c 74 68 2f 6d 65 6d 62 65 72 70 6f 72 74 61 6c } //1 com/priorityhealth/memberportal
		$a_01_1 = {6d 65 6d 62 65 72 70 6f 72 74 61 6c 2e 64 62 } //1 memberportal.db
		$a_01_2 = {67 65 74 43 6c 61 73 73 4c 6f 61 64 65 72 } //1 getClassLoader
		$a_01_3 = {6c 6f 61 64 4c 69 62 73 } //1 loadLibs
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}