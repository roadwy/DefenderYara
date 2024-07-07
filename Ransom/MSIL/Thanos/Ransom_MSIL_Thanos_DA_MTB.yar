
rule Ransom_MSIL_Thanos_DA_MTB{
	meta:
		description = "Ransom:MSIL/Thanos.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {63 33 52 76 63 43 42 42 62 6e 52 70 64 6d 6c 79 64 58 4d } //1 c3RvcCBBbnRpdmlydXM
		$a_81_1 = {63 33 52 76 63 43 44 69 67 4a 78 54 62 33 42 6f 62 33 4d 67 51 32 78 6c 59 57 34 67 55 32 56 79 64 6d 6c 6a 5a 65 4b 41 6e 53 41 } //1 c3RvcCDigJxTb3Bob3MgQ2xlYW4gU2VydmljZeKAnSA
		$a_81_2 = {52 45 53 54 4f 52 45 5f 46 49 4c 45 53 5f 49 4e 46 4f 2e 74 78 74 } //1 RESTORE_FILES_INFO.txt
		$a_81_3 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //1 DisableTaskMgr
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}