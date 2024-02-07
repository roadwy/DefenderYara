
rule Ransom_MSIL_Filecoder_PKA_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.PKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 65 63 72 79 70 74 69 6f 6e 46 69 6c 65 } //01 00  DecryptionFile
		$a_01_1 = {45 6e 63 72 79 70 74 69 6f 6e 46 69 6c 65 } //01 00  EncryptionFile
		$a_01_2 = {46 72 65 65 7a 65 4d 6f 75 73 65 } //01 00  FreezeMouse
		$a_01_3 = {53 61 76 69 74 61 72 52 57 2e 65 78 65 } //01 00  SavitarRW.exe
		$a_81_4 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //01 00  DisableTaskMgr
		$a_81_5 = {73 68 75 74 64 6f 77 6e } //0a 00  shutdown
		$a_80_6 = {61 32 64 58 66 63 34 57 61 42 56 77 } //a2dXfc4WaBVw  0a 00 
		$a_81_7 = {59 6f 75 20 63 61 6e 27 74 20 64 65 63 65 69 76 65 20 6d 65 } //0a 00  You can't deceive me
		$a_01_8 = {53 61 76 69 74 61 72 52 57 5c 53 61 76 69 74 61 72 52 57 5c 6f 62 6a 5c 44 65 62 75 67 5c 53 61 76 69 74 61 72 52 57 2e 70 64 62 } //00 00  SavitarRW\SavitarRW\obj\Debug\SavitarRW.pdb
	condition:
		any of ($a_*)
 
}