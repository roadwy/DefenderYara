
rule Trojan_Win64_PipeMon_H_MTB{
	meta:
		description = "Trojan:Win64/PipeMon.H!MTB,SIGNATURE_TYPE_PEHSTR,0d 00 0d 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 00 70 00 6f 00 6f 00 6c 00 5c 00 70 00 72 00 74 00 70 00 72 00 6f 00 63 00 73 00 5c 00 78 00 36 00 34 00 } //10 spool\prtprocs\x64
		$a_01_1 = {46 61 69 6c 65 64 20 74 6f 20 69 6e 6a 65 63 74 20 74 68 65 20 44 4c 4c } //1 Failed to inject the DLL
		$a_01_2 = {25 73 20 69 6e 6a 65 63 74 20 25 64 20 66 61 69 6c 65 64 20 25 64 } //1 %s inject %d failed %d
		$a_01_3 = {49 00 6e 00 6a 00 65 00 63 00 74 00 69 00 6f 00 6e 00 20 00 46 00 41 00 49 00 4c 00 45 00 44 00 21 00 } //1 Injection FAILED!
		$a_01_4 = {69 6e 6a 65 63 74 20 50 69 64 20 3a 25 64 20 72 65 74 75 72 6e 3a 25 64 } //1 inject Pid :%d return:%d
		$a_01_5 = {57 00 72 00 69 00 74 00 65 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 20 00 46 00 41 00 49 00 4c 00 45 00 44 00 21 00 } //1 WriteProcessMemory FAILED!
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=13
 
}