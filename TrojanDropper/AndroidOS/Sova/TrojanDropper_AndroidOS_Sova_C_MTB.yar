
rule TrojanDropper_AndroidOS_Sova_C_MTB{
	meta:
		description = "TrojanDropper:AndroidOS/Sova.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_00_0 = {69 6e 6a 65 63 74 6c 69 73 74 } //1 injectlist
		$a_00_1 = {69 73 45 6d 75 6c 61 74 6f 72 } //1 isEmulator
		$a_03_2 = {91 02 05 04 23 20 [0-05] 12 01 91 02 05 04 35 21 0f 00 62 02 [0-05] 90 (4a 02 02 03|b7) 62 8e 22 50 02 00 01 d8 01 01 01 28 f0 } //2
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*2) >=4
 
}