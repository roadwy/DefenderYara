
rule Ransom_Win64_FileCryptor_X_MTB{
	meta:
		description = "Ransom:Win64/FileCryptor.X!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_81_0 = {5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 45 78 70 6c 6f 72 65 72 20 20 20 2f 76 20 4e 6f 52 75 6e } //1 \CurrentVersion\Policies\Explorer   /v NoRun
		$a_81_1 = {5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d 20 20 20 2f 76 20 44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //1 \CurrentVersion\Policies\System   /v DisableTaskMgr
		$a_81_2 = {52 61 6e 73 6f 6d 77 61 72 65 5c 46 6f 6e 69 78 } //1 Ransomware\Fonix
		$a_81_3 = {45 6e 64 20 2d 20 47 6f 6f 64 4c 75 63 6b } //1 End - GoodLuck
		$a_81_4 = {45 6e 63 72 79 70 74 69 6f 6e 20 43 6f 6d 70 6c 65 74 65 64 } //1 Encryption Completed
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=4
 
}