
rule Backdoor_Win32_Delf_ADE{
	meta:
		description = "Backdoor:Win32/Delf.ADE,SIGNATURE_TYPE_PEHSTR,11 01 11 01 10 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //100 SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {72 65 6d 6f 74 65 20 6e 65 74 77 6f 72 6b 20 26 20 63 6f 6e 63 74 72 6f 6c 20 73 65 72 76 69 63 65 } //100 remote network & conctrol service
		$a_01_2 = {44 69 73 61 62 6c 65 52 65 67 69 73 74 72 79 54 6f 6f 6c 73 } //10 DisableRegistryTools
		$a_01_3 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //10 CreateToolhelp32Snapshot
		$a_01_4 = {54 6f 6f 6c 68 65 6c 70 33 32 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //10 Toolhelp32ReadProcessMemory
		$a_01_5 = {73 79 73 69 2e 64 6c 6c } //10 sysi.dll
		$a_01_6 = {53 65 72 76 69 63 65 44 6c 6c } //10 ServiceDll
		$a_01_7 = {63 6d 64 20 2f 63 20 64 65 6c 20 } //10 cmd /c del 
		$a_01_8 = {73 76 63 68 6f 73 74 2e 65 78 65 20 2d 6b 20 } //10 svchost.exe -k 
		$a_01_9 = {6d 73 6e 6d 73 67 72 2e } //1 msnmsgr.
		$a_01_10 = {74 72 69 6c 6c 69 61 6e 2e } //1 trillian.
		$a_01_11 = {67 6f 6f 67 6c 65 74 61 6c 6b 2e } //1 googletalk.
		$a_01_12 = {79 61 68 6f 6f 6d 65 73 73 65 6e 67 65 72 2e } //1 yahoomessenger.
		$a_01_13 = {73 76 63 68 6f 73 74 2e } //1 svchost.
		$a_01_14 = {61 76 70 63 63 2e 65 78 } //1 avpcc.ex
		$a_01_15 = {6d 73 69 6d 6e 2e 65 78 } //1 msimn.ex
	condition:
		((#a_01_0  & 1)*100+(#a_01_1  & 1)*100+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_01_5  & 1)*10+(#a_01_6  & 1)*10+(#a_01_7  & 1)*10+(#a_01_8  & 1)*10+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1) >=273
 
}