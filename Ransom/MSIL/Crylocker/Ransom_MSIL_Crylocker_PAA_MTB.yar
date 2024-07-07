
rule Ransom_MSIL_Crylocker_PAA_MTB{
	meta:
		description = "Ransom:MSIL/Crylocker.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {56 69 65 77 5f 65 6e 63 72 79 70 74 5f 66 69 6c 65 5f 6c 69 73 74 } //1 View_encrypt_file_list
		$a_01_1 = {45 00 6e 00 63 00 72 00 79 00 70 00 74 00 69 00 6f 00 6e 00 20 00 43 00 6f 00 6d 00 70 00 6c 00 65 00 74 00 65 00 } //1 Encryption Complete
		$a_01_2 = {73 74 72 46 69 6c 65 54 6f 45 6e 63 72 79 70 74 } //1 strFileToEncrypt
		$a_01_3 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 54 00 61 00 73 00 6b 00 4d 00 67 00 72 00 } //1 DisableTaskMgr
		$a_01_4 = {2e 00 43 00 72 00 79 00 6c 00 6f 00 63 00 6b 00 65 00 72 00 } //1 .Crylocker
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}