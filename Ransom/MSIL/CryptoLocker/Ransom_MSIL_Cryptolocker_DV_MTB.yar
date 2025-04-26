
rule Ransom_MSIL_Cryptolocker_DV_MTB{
	meta:
		description = "Ransom:MSIL/Cryptolocker.DV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,4a 00 4a 00 10 00 00 "
		
	strings :
		$a_81_0 = {44 69 73 63 6f 52 61 6e 73 6f 6d 77 61 72 65 } //50 DiscoRansomware
		$a_81_1 = {76 78 43 72 79 70 74 65 72 } //50 vxCrypter
		$a_81_2 = {52 75 6e 63 6f 75 6e 74 2e 63 72 79 } //50 Runcount.cry
		$a_81_3 = {68 69 64 64 65 6e 20 74 65 61 72 } //50 hidden tear
		$a_81_4 = {63 68 65 63 6b 69 70 2e 64 79 6e 64 6e 73 2e 6f 72 67 } //20 checkip.dyndns.org
		$a_81_5 = {41 4c 4c 20 59 4f 55 52 20 46 49 4c 45 53 20 41 52 45 20 45 4e 43 52 59 50 54 45 44 } //20 ALL YOUR FILES ARE ENCRYPTED
		$a_81_6 = {48 6f 77 20 54 6f 20 44 65 63 72 79 70 74 20 4d 79 20 46 69 6c 65 73 } //20 How To Decrypt My Files
		$a_81_7 = {69 5f 61 6d 5f 61 5f 64 6f 6c 70 68 69 6e } //20 i_am_a_dolphin
		$a_81_8 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //3 DisableTaskMgr
		$a_81_9 = {44 65 63 72 79 70 74 20 66 69 6c 65 73 } //3 Decrypt files
		$a_81_10 = {44 65 74 65 63 74 53 61 6e 64 62 6f 78 69 65 } //3 DetectSandboxie
		$a_81_11 = {2e 64 6f 6c 70 68 69 6e } //3 .dolphin
		$a_81_12 = {65 6e 63 72 79 70 74 } //1 encrypt
		$a_81_13 = {4c 6f 63 6b 65 64 } //1 Locked
		$a_81_14 = {44 65 74 65 63 74 44 65 62 75 67 67 65 72 } //1 DetectDebugger
		$a_81_15 = {72 61 6e 73 6f 6d 77 61 72 65 } //1 ransomware
	condition:
		((#a_81_0  & 1)*50+(#a_81_1  & 1)*50+(#a_81_2  & 1)*50+(#a_81_3  & 1)*50+(#a_81_4  & 1)*20+(#a_81_5  & 1)*20+(#a_81_6  & 1)*20+(#a_81_7  & 1)*20+(#a_81_8  & 1)*3+(#a_81_9  & 1)*3+(#a_81_10  & 1)*3+(#a_81_11  & 1)*3+(#a_81_12  & 1)*1+(#a_81_13  & 1)*1+(#a_81_14  & 1)*1+(#a_81_15  & 1)*1) >=74
 
}