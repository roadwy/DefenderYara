
rule TrojanSpy_AndroidOS_Banker_AE_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.AE!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 77 61 70 53 6d 73 4d 65 6e 61 67 65 72 } //1 swapSmsMenager
		$a_01_1 = {73 74 61 72 74 43 6c 65 61 72 43 61 73 68 } //1 startClearCash
		$a_00_2 = {63 61 6c 6c 43 61 70 61 62 6c 65 50 68 6f 6e 65 41 63 63 6f 75 6e 74 73 } //1 callCapablePhoneAccounts
		$a_00_3 = {63 68 65 63 6b 43 61 6c 6c 69 6e 67 4f 72 53 65 6c 66 50 65 72 6d 69 73 73 69 6f 6e } //1 checkCallingOrSelfPermission
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}