
rule Trojan_Win32_Keylogger_AMAK_MTB{
	meta:
		description = "Trojan:Win32/Keylogger.AMAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 6c 61 73 68 42 75 66 00 47 65 74 44 75 6d 70 65 72 44 4c 4c 4e 61 6d 65 00 47 65 74 44 75 6d 70 65 72 44 4c 4c 56 65 72 73 69 6f 6e 00 49 6e 73 74 61 6c 6c 44 75 6d 70 65 72 44 4c 4c 00 4c 61 73 74 4b 65 79 53 74 72 00 50 61 75 73 65 4c 6f 67 00 55 6e 69 6e 73 74 61 6c 6c 44 75 6d 70 65 72 44 4c 4c } //3
		$a_01_1 = {44 75 6d 70 65 72 44 4c 4c 4d 75 74 65 78 } //1 DumperDLLMutex
		$a_01_2 = {47 65 74 43 6f 6d 70 75 74 65 72 4e 61 6d 65 20 46 61 69 6c 65 64 } //1 GetComputerName Failed
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}