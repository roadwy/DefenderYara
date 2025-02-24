
rule TrojanSpy_AndroidOS_Dabom_C_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Dabom.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {35 53 15 00 46 00 06 04 44 01 07 03 39 00 0a 00 12 00 b7 10 b0 02 d8 03 03 01 d8 04 04 02 28 f1 } //1
		$a_01_1 = {73 6d 73 62 6f 6d 62 65 72 } //1 smsbomber
		$a_01_2 = {44 65 6c 65 74 65 41 63 63 6f 75 6e 74 41 63 74 69 76 69 74 79 } //1 DeleteAccountActivity
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}