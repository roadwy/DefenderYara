
rule TrojanSpy_AndroidOS_SAgnt_O_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.O!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 2f 70 6f 73 74 6d 61 6e 2f 73 65 61 72 63 68 2f 6f 6e 6c 69 6e 65 2f 61 63 74 69 76 69 74 79 } //1 com/postman/search/online/activity
		$a_01_1 = {72 65 6d 6f 76 65 53 63 72 65 65 6e 4c 6f 63 6b 43 6f 64 65 } //1 removeScreenLockCode
		$a_01_2 = {68 69 64 65 49 63 6f 6e } //1 hideIcon
		$a_01_3 = {69 73 53 63 72 6c 6f 63 6b 65 64 } //1 isScrlocked
		$a_01_4 = {6c 6f 63 6b 53 63 72 65 65 6e 57 69 74 68 43 6f 64 65 } //1 lockScreenWithCode
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}