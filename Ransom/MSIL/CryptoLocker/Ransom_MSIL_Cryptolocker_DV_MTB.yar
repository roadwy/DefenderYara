
rule Ransom_MSIL_Cryptolocker_DV_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.DV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,4a 00 4a 00 10 00 00 32 00 "
		
	strings :
		$a_81_0 = {44 69 73 63 6f 52 61 6e 73 6f 6d 77 61 72 65 } //32 00  DiscoRansomware
		$a_81_1 = {76 78 43 72 79 70 74 65 72 } //32 00  vxCrypter
		$a_81_2 = {52 75 6e 63 6f 75 6e 74 2e 63 72 79 } //32 00  Runcount.cry
		$a_81_3 = {68 69 64 64 65 6e 20 74 65 61 72 } //14 00  hidden tear
		$a_81_4 = {63 68 65 63 6b 69 70 2e 64 79 6e 64 6e 73 2e 6f 72 67 } //14 00  checkip.dyndns.org
		$a_81_5 = {41 4c 4c 20 59 4f 55 52 20 46 49 4c 45 53 20 41 52 45 20 45 4e 43 52 59 50 54 45 44 } //14 00  ALL YOUR FILES ARE ENCRYPTED
		$a_81_6 = {48 6f 77 20 54 6f 20 44 65 63 72 79 70 74 20 4d 79 20 46 69 6c 65 73 } //14 00  How To Decrypt My Files
		$a_81_7 = {69 5f 61 6d 5f 61 5f 64 6f 6c 70 68 69 6e } //03 00  i_am_a_dolphin
		$a_81_8 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //03 00  DisableTaskMgr
		$a_81_9 = {44 65 63 72 79 70 74 20 66 69 6c 65 73 } //03 00  Decrypt files
		$a_81_10 = {44 65 74 65 63 74 53 61 6e 64 62 6f 78 69 65 } //03 00  DetectSandboxie
		$a_81_11 = {2e 64 6f 6c 70 68 69 6e } //01 00  .dolphin
		$a_81_12 = {65 6e 63 72 79 70 74 } //01 00  encrypt
		$a_81_13 = {4c 6f 63 6b 65 64 } //01 00  Locked
		$a_81_14 = {44 65 74 65 63 74 44 65 62 75 67 67 65 72 } //01 00  DetectDebugger
		$a_81_15 = {72 61 6e 73 6f 6d 77 61 72 65 } //00 00  ransomware
	condition:
		any of ($a_*)
 
}