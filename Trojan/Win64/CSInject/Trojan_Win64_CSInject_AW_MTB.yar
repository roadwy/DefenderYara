
rule Trojan_Win64_CSInject_AW_MTB{
	meta:
		description = "Trojan:Win64/CSInject.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 45 53 20 50 72 6f 63 65 73 73 20 48 6f 6c 6c 6f 77 69 6e 67 2e 65 78 65 } //01 00  AES Process Hollowing.exe
		$a_01_1 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  WriteProcessMemory
		$a_01_2 = {52 65 73 75 6d 65 54 68 72 65 61 64 } //01 00  ResumeThread
		$a_01_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00  CreateDecryptor
	condition:
		any of ($a_*)
 
}