
rule Trojan_Win32_Raccoon_CCBM_MTB{
	meta:
		description = "Trojan:Win32/Raccoon.CCBM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_01_0 = {73 67 6e 6c 5f } //1 sgnl_
		$a_01_1 = {74 6c 67 72 6d 5f } //1 tlgrm_
		$a_01_2 = {67 72 62 72 5f } //1 grbr_
		$a_01_3 = {64 73 63 72 64 5f } //1 dscrd_
		$a_01_4 = {77 6c 74 73 5f } //1 wlts_
		$a_01_5 = {73 63 72 6e 73 68 74 5f } //1 scrnsht_
		$a_01_6 = {55 52 4c 3a 25 73 } //1 URL:%s
		$a_01_7 = {55 53 52 3a 25 73 } //1 USR:%s
		$a_01_8 = {50 41 53 53 3a 25 73 } //1 PASS:%s
		$a_01_9 = {6d 61 63 68 69 6e 65 49 64 3d } //1 machineId=
		$a_01_10 = {26 63 6f 6e 66 69 67 49 64 3d } //1 &configId=
		$a_01_11 = {4c 6f 67 69 6e 20 44 61 74 61 } //1 Login Data
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=12
 
}