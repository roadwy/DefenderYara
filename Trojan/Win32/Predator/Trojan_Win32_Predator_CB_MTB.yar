
rule Trojan_Win32_Predator_CB_MTB{
	meta:
		description = "Trojan:Win32/Predator.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {7a 00 65 00 72 00 6f 00 78 00 65 00 72 00 6f 00 2e 00 64 00 6c 00 6c 00 } //1 zeroxero.dll
		$a_01_1 = {48 00 69 00 49 00 61 00 6d 00 4d 00 75 00 74 00 65 00 78 00 } //1 HiIamMutex
		$a_01_2 = {64 00 73 00 65 00 72 00 66 00 2e 00 65 00 78 00 65 00 } //1 dserf.exe
		$a_01_3 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}