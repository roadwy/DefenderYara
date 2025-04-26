
rule Trojan_Win32_Farfli_AO_MTB{
	meta:
		description = "Trojan:Win32/Farfli.AO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {61 48 52 30 63 44 6f 76 4c 7a 45 79 4e 43 34 78 4e 54 59 75 4d 54 51 34 4c 6a 63 79 4f 6a 67 33 4f 44 6b 76 64 48 4e 6c 64 48 56 77 4c 6a 49 75 4e 43 34 33 4c 6d 56 34 5a 51 } //1 aHR0cDovLzEyNC4xNTYuMTQ4LjcyOjg3ODkvdHNldHVwLjIuNC43LmV4ZQ
		$a_01_1 = {43 3a 2f 55 73 65 72 73 2f 50 75 62 6c 69 63 2f 44 6f 63 75 6d 65 6e 74 73 2f 50 6f 77 65 72 6d 6f 6e 73 74 65 72 2e 65 78 65 } //1 C:/Users/Public/Documents/Powermonster.exe
		$a_01_2 = {43 3a 2f 55 73 65 72 73 2f 50 75 62 6c 69 63 2f 44 6f 63 75 6d 65 6e 74 73 2f 75 6e 7a 69 70 2e 65 78 65 } //1 C:/Users/Public/Documents/unzip.exe
		$a_01_3 = {62 65 6e 73 6f 6e 2e 70 64 62 } //1 benson.pdb
		$a_01_4 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
		$a_01_5 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_01_6 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}