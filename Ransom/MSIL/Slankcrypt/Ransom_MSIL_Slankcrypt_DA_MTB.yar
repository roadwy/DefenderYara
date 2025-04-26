
rule Ransom_MSIL_Slankcrypt_DA_MTB{
	meta:
		description = "Ransom:MSIL/Slankcrypt.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {41 4c 4c 20 59 4f 55 52 20 46 49 4c 45 53 20 41 52 45 20 45 4e 43 52 59 50 54 45 44 } //1 ALL YOUR FILES ARE ENCRYPTED
		$a_81_1 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //1 DisableTaskMgr
		$a_81_2 = {44 45 41 52 20 49 4e 46 45 43 54 45 44 20 43 4c 49 45 4e 54 53 } //1 DEAR INFECTED CLIENTS
		$a_81_3 = {2e 73 6c 61 6e 6b } //1 .slank
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}