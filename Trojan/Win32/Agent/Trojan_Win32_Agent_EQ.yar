
rule Trojan_Win32_Agent_EQ{
	meta:
		description = "Trojan:Win32/Agent.EQ,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_00_0 = {68 65 6c 70 2e 64 6c 6c } //1 help.dll
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 53 65 74 75 70 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Setup
		$a_00_2 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 42 49 54 53 5c 50 61 72 61 6d 65 74 65 72 73 } //1 SYSTEM\CurrentControlSet\Services\BITS\Parameters
		$a_00_3 = {53 59 53 54 45 4d 5c 43 6f 6e 74 72 6f 6c 53 65 74 30 30 33 5c 53 65 72 76 69 63 65 73 5c 42 49 54 53 5c 50 61 72 61 6d 65 74 65 72 73 } //1 SYSTEM\ControlSet003\Services\BITS\Parameters
		$a_00_4 = {46 72 65 65 20 44 4c 4c 20 44 6f 6e 65 21 } //1 Free DLL Done!
		$a_00_5 = {44 69 73 61 62 6c 65 52 65 67 69 73 74 72 79 54 6f 6f 6c 73 } //1 DisableRegistryTools
		$a_00_6 = {77 69 6e 6d 6d 2e 64 6c 6c } //1 winmm.dll
		$a_02_7 = {52 65 6d 6f 74 65 20 6e 65 74 43 6f 6e 74 72 6f 6c 20 53 65 72 76 69 63 65 3c 2f 64 69 73 3e 3c 64 65 73 3e 72 65 6d 6f 74 65 20 6e 65 74 77 6f 72 6b 20 26 20 63 6f 6e 63 74 72 6f 6c 20 73 65 72 76 69 63 65 3c 2f 64 65 73 3e 3c 69 6e 66 3e [0-50] 3a } //1
		$a_00_8 = {51 33 36 30 53 61 66 65 4d 6f 6e 43 6c 61 73 73 } //1 Q360SafeMonClass
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_02_7  & 1)*1+(#a_00_8  & 1)*1) >=9
 
}