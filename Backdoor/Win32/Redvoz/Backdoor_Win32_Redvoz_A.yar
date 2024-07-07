
rule Backdoor_Win32_Redvoz_A{
	meta:
		description = "Backdoor:Win32/Redvoz.A,SIGNATURE_TYPE_PEHSTR,09 00 09 00 0c 00 00 "
		
	strings :
		$a_01_0 = {73 65 72 76 69 63 65 2c 20 72 65 73 3d } //1 service, res=
		$a_01_1 = {49 6e 6a 65 63 74 69 6f 6e 54 68 72 65 61 64 20 63 6f 6d 70 6c 65 74 65 } //1 InjectionThread complete
		$a_01_2 = {3c 44 4c 4c 20 64 69 65 73 3e 20 65 76 65 6e 74 } //1 <DLL dies> event
		$a_01_3 = {74 72 79 69 6e 67 20 3c 25 73 3e 20 77 69 74 68 20 3c 25 73 3e } //1 trying <%s> with <%s>
		$a_01_4 = {44 4c 4c 20 69 6e 6a 65 63 74 65 64 21 } //1 DLL injected!
		$a_01_5 = {74 68 72 65 61 64 20 63 6f 6d 70 6c 65 74 65 20 28 25 69 29 2e } //1 thread complete (%i).
		$a_01_6 = {74 68 72 65 61 64 20 69 6e 6a 65 63 74 65 64 20 28 25 69 29 2e } //1 thread injected (%i).
		$a_01_7 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 28 29 20 6f 6b } //1 WriteProcessMemory() ok
		$a_01_8 = {66 69 6c 65 20 3c 25 73 3e } //1 file <%s>
		$a_01_9 = {77 72 69 74 69 6e 67 20 74 6f 20 48 4b 4c 4d } //1 writing to HKLM
		$a_01_10 = {6d 79 20 70 6f 72 74 20 5b 25 69 5d } //1 my port [%i]
		$a_01_11 = {2a 75 70 64 61 74 65 20 22 } //1 *update "
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=9
 
}