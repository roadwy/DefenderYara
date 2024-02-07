
rule Ransom_MSIL_Cryptolocker_EE_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.EE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,4a 00 4a 00 08 00 00 32 00 "
		
	strings :
		$a_81_0 = {41 70 6c 69 63 61 74 69 76 6f } //32 00  Aplicativo
		$a_81_1 = {41 6c 6c 20 4f 66 20 59 6f 75 72 20 46 69 6c 65 73 20 41 72 65 20 44 65 63 72 79 70 74 65 64 } //14 00  All Of Your Files Are Decrypted
		$a_81_2 = {74 6d 72 5f 65 6e 63 72 79 70 74 } //14 00  tmr_encrypt
		$a_81_3 = {2e 6d 61 6c 6b 69 } //03 00  .malki
		$a_81_4 = {62 79 74 65 73 54 6f 42 65 45 6e 63 72 79 70 74 65 64 } //03 00  bytesToBeEncrypted
		$a_81_5 = {52 61 6e 73 6f 6d 77 61 72 65 20 76 69 72 75 73 } //01 00  Ransomware virus
		$a_81_6 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //01 00  DisableTaskMgr
		$a_81_7 = {4c 6f 63 6b 53 63 72 65 65 6e } //00 00  LockScreen
	condition:
		any of ($a_*)
 
}