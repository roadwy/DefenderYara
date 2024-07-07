
rule Ransom_MSIL_Filecoder_PKA_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.PKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 09 00 00 "
		
	strings :
		$a_01_0 = {44 65 63 72 79 70 74 69 6f 6e 46 69 6c 65 } //1 DecryptionFile
		$a_01_1 = {45 6e 63 72 79 70 74 69 6f 6e 46 69 6c 65 } //1 EncryptionFile
		$a_01_2 = {46 72 65 65 7a 65 4d 6f 75 73 65 } //1 FreezeMouse
		$a_01_3 = {53 61 76 69 74 61 72 52 57 2e 65 78 65 } //1 SavitarRW.exe
		$a_81_4 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //1 DisableTaskMgr
		$a_81_5 = {73 68 75 74 64 6f 77 6e } //1 shutdown
		$a_80_6 = {61 32 64 58 66 63 34 57 61 42 56 77 } //a2dXfc4WaBVw  10
		$a_81_7 = {59 6f 75 20 63 61 6e 27 74 20 64 65 63 65 69 76 65 20 6d 65 } //10 You can't deceive me
		$a_01_8 = {53 61 76 69 74 61 72 52 57 5c 53 61 76 69 74 61 72 52 57 5c 6f 62 6a 5c 44 65 62 75 67 5c 53 61 76 69 74 61 72 52 57 2e 70 64 62 } //10 SavitarRW\SavitarRW\obj\Debug\SavitarRW.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_80_6  & 1)*10+(#a_81_7  & 1)*10+(#a_01_8  & 1)*10) >=35
 
}