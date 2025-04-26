
rule Trojan_Win32_Agent_NAO{
	meta:
		description = "Trojan:Win32/Agent.NAO,SIGNATURE_TYPE_PEHSTR,47 00 47 00 08 00 00 "
		
	strings :
		$a_01_0 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 70 63 69 68 64 64 2e 73 79 73 } //10 %SystemRoot%\system32\drivers\pcihdd.sys
		$a_01_1 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 53 79 73 74 65 6d 33 32 5c 55 73 65 72 69 6e 69 74 2e 65 78 65 } //10 %SystemRoot%\System32\Userinit.exe
		$a_01_2 = {57 72 69 74 65 46 69 6c 65 } //10 WriteFile
		$a_01_3 = {52 74 6c 5a 65 72 6f 4d 65 6d 6f 72 79 } //10 RtlZeroMemory
		$a_01_4 = {4f 70 65 6e 53 65 72 76 69 63 65 41 } //10 OpenServiceA
		$a_01_5 = {44 65 6c 65 74 65 46 69 6c 65 41 } //10 DeleteFileA
		$a_01_6 = {44 65 6c 65 74 65 53 65 72 76 69 63 65 } //10 DeleteService
		$a_01_7 = {c7 42 0c 6d 2f 74 65 c7 42 10 73 74 2e 63 c7 42 14 65 72 00 00 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*1) >=71
 
}