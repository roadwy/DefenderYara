
rule Ransom_MSIL_Bingom_DA_MTB{
	meta:
		description = "Ransom:MSIL/Bingom.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {5a 69 6e 7a 69 6e 56 69 72 75 73 } //1 ZinzinVirus
		$a_81_1 = {54 61 6d 70 65 72 50 72 6f 74 65 63 74 69 6f 6e } //1 TamperProtection
		$a_81_2 = {44 69 73 61 62 6c 65 41 6e 74 69 53 70 79 77 61 72 65 } //1 DisableAntiSpyware
		$a_81_3 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //1 DisableTaskMgr
		$a_81_4 = {62 79 74 65 73 54 6f 42 65 45 6e 63 72 79 70 74 65 64 } //1 bytesToBeEncrypted
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}