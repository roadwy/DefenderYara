
rule TrojanSpy_AndroidOS_Samsapo_AS_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Samsapo.AS!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {6f 6f 70 73 73 70 6f 6f 2e 72 75 2f 69 6e 64 65 78 2e 70 68 70 } //1 oopsspoo.ru/index.php
		$a_00_1 = {68 61 73 5f 70 68 6f 6e 65 5f 6e 75 6d 62 65 72 } //1 has_phone_number
		$a_00_2 = {73 69 6c 65 6e 63 65 52 69 6e 67 65 72 } //1 silenceRinger
		$a_01_3 = {42 6c 6f 63 6b 4e 75 6d 73 } //1 BlockNums
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}