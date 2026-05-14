
rule Trojan_Win64_Injector_AMTB{
	meta:
		description = "Trojan:Win64/Injector!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {52 74 6c 41 64 6a 75 73 74 50 72 69 76 69 6c 65 67 65 } //RtlAdjustPrivilege  1
		$a_80_1 = {4e 74 52 61 69 73 65 48 61 72 64 45 72 72 6f 72 } //NtRaiseHardError  1
		$a_80_2 = {6c 73 61 73 73 2e 65 78 65 } //lsass.exe  1
		$a_80_3 = {4e 74 51 75 65 72 79 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79 } //NtQueryVirtualMemory  1
		$a_80_4 = {4e 74 51 75 65 72 79 53 79 73 74 65 6d 49 6e 66 6f 72 6d 61 74 69 6f 6e } //NtQuerySystemInformation  1
		$a_80_5 = {51 57 4e 6a 5a 57 78 4e 62 32 52 6c 49 44 30 67 4d 41 70 54 5a 57 35 7a 61 58 52 70 64 6d 6c 30 65 53 41 39 49 44 45 75 4d 77 70 42 59 32 4e 6c 62 47 56 79 59 58 52 70 62 32 34 67 50 53 41 77 } //QWNjZWxNb2RlID0gMApTZW5zaXRpdml0eSA9IDEuMwpBY2NlbGVyYXRpb24gPSAw  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}