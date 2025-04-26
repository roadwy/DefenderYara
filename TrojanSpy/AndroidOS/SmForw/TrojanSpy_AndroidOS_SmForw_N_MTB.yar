
rule TrojanSpy_AndroidOS_SmForw_N_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmForw.N!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6d 2f 66 64 65 2f 67 73 41 63 74 69 76 69 74 79 } //1 com/fde/gsActivity
		$a_00_1 = {64 64 4d 79 57 65 62 41 63 74 69 76 69 74 79 } //1 ddMyWebActivity
		$a_00_2 = {68 66 43 61 6e 63 65 6c 4e 6f 74 69 63 65 53 65 72 76 69 63 65 } //1 hfCancelNoticeService
		$a_00_3 = {76 67 4d 61 69 6e 53 65 72 76 69 63 65 } //1 vgMainService
		$a_00_4 = {65 73 4d 79 41 70 70 6c 69 63 61 74 69 6f 6e } //1 esMyApplication
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}