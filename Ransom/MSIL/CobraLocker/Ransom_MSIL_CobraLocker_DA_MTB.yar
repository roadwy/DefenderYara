
rule Ransom_MSIL_CobraLocker_DA_MTB{
	meta:
		description = "Ransom:MSIL/CobraLocker.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {64 65 6c 20 43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c 54 61 73 6b 6d 67 72 2e 65 78 65 } //1 del C:\Windows\System32\Taskmgr.exe
		$a_81_1 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //1 DisableTaskMgr
		$a_81_2 = {44 69 73 61 62 6c 65 52 65 67 69 73 74 72 79 54 6f 6f 6c 73 } //1 DisableRegistryTools
		$a_81_3 = {45 6e 63 72 79 70 74 46 69 6c 65 } //1 EncryptFile
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}