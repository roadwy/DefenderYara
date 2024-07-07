
rule Trojan_AndroidOS_GriftHorse_M_MTB{
	meta:
		description = "Trojan:AndroidOS/GriftHorse.M!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {4c 63 6f 6d 2f 90 02 20 4d 61 69 6e 41 63 74 69 76 69 74 79 90 00 } //1
		$a_03_1 = {70 73 3a 2f 2f 64 90 02 17 2e 63 6c 6f 75 64 66 72 6f 6e 74 2e 6e 65 74 2f 63 6f 6d 2e 90 02 35 2e 68 74 6d 6c 90 00 } //2
		$a_00_2 = {73 68 6f 75 6c 64 4f 76 65 72 72 69 64 65 55 72 6c 4c 6f 61 64 69 6e 67 } //1 shouldOverrideUrlLoading
		$a_00_3 = {72 65 67 69 73 74 65 72 41 6e 64 47 65 74 49 6e 73 74 61 6e 63 65 } //1 registerAndGetInstance
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}