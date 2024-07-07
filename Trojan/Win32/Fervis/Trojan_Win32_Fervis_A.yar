
rule Trojan_Win32_Fervis_A{
	meta:
		description = "Trojan:Win32/Fervis.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {80 01 08 8a 51 01 41 84 d2 75 f5 } //1
		$a_01_1 = {53 41 40 42 43 83 e8 01 83 eb 01 83 e9 01 83 ea 01 5b e9 } //1
		$a_01_2 = {8b 7c 24 40 33 f6 8a 04 3e 3c 61 7c 1e 3c 7a 7f 1a 8b e9 69 ed 01 04 00 00 0f be d0 } //1
		$a_00_3 = {53 65 74 57 69 6e 64 6f 77 54 65 78 74 41 } //1 SetWindowTextA
		$a_01_4 = {47 65 74 53 79 73 74 65 6d 44 69 72 65 63 74 6f 72 79 41 } //1 GetSystemDirectoryA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}