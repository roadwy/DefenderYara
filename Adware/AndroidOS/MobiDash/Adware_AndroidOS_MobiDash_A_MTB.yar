
rule Adware_AndroidOS_MobiDash_A_MTB{
	meta:
		description = "Adware:AndroidOS/MobiDash.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {60 00 98 00 6f 20 ec 09 98 00 6e 10 91 0f 08 00 52 81 dc 01 b7 91 59 89 dc 01 dd 02 09 04 12 03 12 14 39 02 04 00 12 12 28 02 } //3
		$a_01_1 = {63 34 30 30 66 31 32 38 65 38 64 30 33 35 30 32 38 39 37 65 38 62 36 61 63 31 64 37 36 39 35 30 2e 63 6f 6d 2f } //3 c400f128e8d03502897e8b6ac1d76950.com/
		$a_03_2 = {6e 65 74 2f 90 02 20 4d 61 69 6e 41 63 74 69 76 69 74 79 24 61 90 00 } //1
		$a_01_3 = {50 72 65 6c 6f 61 64 49 6e 66 6f } //1 PreloadInfo
		$a_01_4 = {4c 6f 63 6b 73 63 72 65 65 6e } //1 Lockscreen
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}