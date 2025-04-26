
rule Trojan_Win64_ShellcodeInject_INC_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeInject.INC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {55 53 41 47 45 3a 20 72 65 64 5f 76 61 6e 69 74 79 2e 65 78 65 20 5b 54 41 52 47 45 54 5f 50 49 44 5f 54 4f 5f 52 45 46 4c 45 43 54 5d } //1 USAGE: red_vanity.exe [TARGET_PID_TO_REFLECT]
		$a_01_1 = {41 6c 6c 6f 63 61 74 65 64 20 73 70 61 63 65 20 66 6f 72 20 73 68 65 6c 6c 63 6f 64 65 20 69 6e 20 73 74 61 72 74 20 61 64 64 72 65 73 73 3a } //1 Allocated space for shellcode in start address:
		$a_01_2 = {46 61 69 6c 65 64 20 74 6f 20 74 65 72 6d 69 6e 61 74 65 20 66 6f 72 6b 65 64 20 70 72 6f 63 65 73 73 } //1 Failed to terminate forked process
		$a_01_3 = {47 6f 74 20 61 20 68 61 6e 64 6c 65 20 74 6f 20 50 49 44 20 25 64 20 73 75 63 63 65 73 73 66 75 6c 6c 79 } //1 Got a handle to PID %d successfully
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}