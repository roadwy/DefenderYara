
rule TrojanSpy_AndroidOS_SmForw_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmForw.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {53 65 6e 64 50 6f 6b 65 } //1 SendPoke
		$a_00_1 = {67 65 74 54 65 6c 43 6f 6d 70 61 6e 79 } //1 getTelCompany
		$a_00_2 = {68 70 5f 67 65 74 73 6d 73 62 6c 6f 63 6b 73 74 61 74 65 2e 70 68 70 3f 74 65 6c 6e 75 6d } //1 hp_getsmsblockstate.php?telnum
		$a_00_3 = {69 6e 64 65 78 2e 70 68 70 3f 74 79 70 65 3d 72 65 63 65 69 76 65 73 6d 73 26 74 65 6c 6e 75 6d } //1 index.php?type=receivesms&telnum
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule TrojanSpy_AndroidOS_SmForw_B_MTB_2{
	meta:
		description = "TrojanSpy:AndroidOS/SmForw.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {68 70 5f 67 65 74 73 6d 73 62 6c 6f 63 6b 73 74 61 74 65 2e 70 68 70 } //1 hp_getsmsblockstate.php
		$a_00_1 = {72 65 63 65 69 76 65 73 6d 73 26 74 65 6c 6e 75 6d } //1 receivesms&telnum
		$a_00_2 = {74 65 6c 5f 62 6c 6f 63 6b 63 61 6c 6c 73 74 61 74 65 } //1 tel_blockcallstate
		$a_00_3 = {67 65 74 50 68 6f 6e 65 4e 75 6d 62 65 72 } //1 getPhoneNumber
		$a_00_4 = {64 6f 53 63 61 6e 4e 65 74 } //1 doScanNet
		$a_02_5 = {4c 63 6f 6d [0-17] 43 6f 6e 6e 4d 61 63 68 69 6e 65 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_02_5  & 1)*1) >=6
 
}