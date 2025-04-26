
rule TrojanSpy_AndroidOS_Piom_D{
	meta:
		description = "TrojanSpy:AndroidOS/Piom.D,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {47 65 6e 65 72 61 74 65 55 72 6c 4b 6e 6f 63 6b } //1 GenerateUrlKnock
		$a_01_1 = {73 65 74 48 74 74 70 56 65 72 } //1 setHttpVer
		$a_01_2 = {73 74 61 72 74 4c 6f 61 64 65 72 41 63 74 69 76 69 74 79 } //1 startLoaderActivity
		$a_01_3 = {73 74 61 72 74 5f 77 6f 72 6b 5f 6d 65 } //1 start_work_me
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}