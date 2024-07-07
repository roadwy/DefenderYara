
rule TrojanSpy_AndroidOS_Wroba_I_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Wroba.I!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {42 4b 5f 43 41 4c 4c 5f 4c 49 53 54 } //3 BK_CALL_LIST
		$a_01_1 = {4e 4f 42 41 4e 4b 55 52 4c } //1 NOBANKURL
		$a_01_2 = {2f 73 65 72 76 6c 65 74 2f 43 6f 6e 74 61 63 74 73 55 70 6c 6f 61 64 } //1 /servlet/ContactsUpload
		$a_01_3 = {41 75 74 42 61 6e 6b 49 6e 74 65 72 } //1 AutBankInter
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}