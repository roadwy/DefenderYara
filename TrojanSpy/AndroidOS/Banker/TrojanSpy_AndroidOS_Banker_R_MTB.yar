
rule TrojanSpy_AndroidOS_Banker_R_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.R!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {35 21 0f 00 62 02 ?? 04 ?? 03 04 01 4a 02 02 03 b7 62 8e 22 50 02 00 01 d8 01 01 01 28 f0 } //1
		$a_00_1 = {70 65 72 66 6f 72 6d 41 63 74 69 6f 6e } //1 performAction
		$a_00_2 = {70 65 72 66 6f 72 6d 47 6c 6f 62 61 6c 41 63 74 69 6f 6e } //1 performGlobalAction
		$a_00_3 = {73 65 74 41 75 74 6f 43 61 6e 63 65 6c } //1 setAutoCancel
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}