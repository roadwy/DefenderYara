
rule Ransom_MSIL_HiddenTear_DL_MTB{
	meta:
		description = "Ransom:MSIL/HiddenTear.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 07 00 00 "
		
	strings :
		$a_80_0 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //DisableTaskMgr  10
		$a_81_1 = {52 61 6e 73 6f 6d 77 61 72 65 32 2e 30 } //1 Ransomware2.0
		$a_81_2 = {45 6e 63 72 79 70 74 46 69 6c 65 } //1 EncryptFile
		$a_81_3 = {52 65 61 64 54 6f 52 65 73 74 6f 72 65 2e 74 78 74 } //1 ReadToRestore.txt
		$a_81_4 = {41 6c 6c 20 79 6f 75 72 20 46 69 6c 65 73 20 61 72 65 20 45 6e 63 72 79 70 74 65 64 } //1 All your Files are Encrypted
		$a_81_5 = {4d 61 6c 77 61 72 65 20 32 2e 30 } //1 Malware 2.0
		$a_81_6 = {4d 61 6c 77 61 72 65 5f 32 2e 5f 30 2e 50 61 79 6c 6f 61 64 73 } //1 Malware_2._0.Payloads
	condition:
		((#a_80_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=12
 
}