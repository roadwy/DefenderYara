
rule Ransom_MSIL_Cryptolocker_PAI_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.PAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 55 53 53 49 45 20 52 41 4e 53 4f 4d 57 41 52 45 } //1 PUSSIE RANSOMWARE
		$a_01_1 = {50 75 73 73 69 65 20 4c 6f 63 6b 65 72 2e 70 64 62 } //1 Pussie Locker.pdb
		$a_01_2 = {44 00 69 00 73 00 61 00 62 00 6c 00 65 00 54 00 61 00 73 00 6b 00 4d 00 67 00 72 00 } //1 DisableTaskMgr
		$a_01_3 = {50 00 72 00 6f 00 63 00 65 00 73 00 73 00 68 00 61 00 63 00 6b 00 65 00 72 00 } //1 Processhacker
		$a_01_4 = {6b 69 6c 6c 20 76 69 72 75 73 } //1 kill virus
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}