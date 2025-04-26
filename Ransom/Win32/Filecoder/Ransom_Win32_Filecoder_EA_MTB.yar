
rule Ransom_Win32_Filecoder_EA_MTB{
	meta:
		description = "Ransom:Win32/Filecoder.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {45 6e 63 72 79 70 74 69 6f 6e 20 43 6f 6d 70 6c 65 74 65 64 20 21 21 21 } //1 Encryption Completed !!!
		$a_81_1 = {2e 6f 6e 69 6f 6e 2e 70 65 74 2f 68 74 74 70 2f 67 65 74 2e 70 68 70 } //1 .onion.pet/http/get.php
		$a_81_2 = {7e 52 61 6e 73 6f 6d 77 61 72 65 } //1 ~Ransomware
		$a_81_3 = {63 72 79 70 74 6f 70 70 38 30 30 } //1 cryptopp800
		$a_81_4 = {2f 76 20 4e 6f 52 75 6e 4e 6f 77 42 61 63 6b 75 70 20 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 31 20 2f 66 } //1 /v NoRunNowBackup  /t REG_DWORD /d 1 /f
		$a_81_5 = {2f 76 20 44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 20 20 2f 74 20 52 45 47 5f 44 57 4f 52 44 20 2f 64 20 30 20 2f 66 } //1 /v DisableTaskMgr  /t REG_DWORD /d 0 /f
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}