
rule Ransom_MSIL_LogonUI_DA_MTB{
	meta:
		description = "Ransom:MSIL/LogonUI.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {4c 6f 67 6f 6e 55 49 52 61 6e 73 6f 6d 77 61 72 65 } //1 LogonUIRansomware
		$a_81_1 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //1 DisableTaskMgr
		$a_81_2 = {45 6e 74 65 72 20 44 65 63 72 79 70 74 69 6f 6e 20 4b 65 79 } //1 Enter Decryption Key
		$a_81_3 = {69 63 6f 6e 66 69 6e 64 65 72 5f 6c 6f 63 6b } //1 iconfinder_lock
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}