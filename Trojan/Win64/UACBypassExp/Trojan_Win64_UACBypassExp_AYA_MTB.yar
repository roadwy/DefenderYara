
rule Trojan_Win64_UACBypassExp_AYA_MTB{
	meta:
		description = "Trojan:Win64/UACBypassExp.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 75 61 63 62 79 70 70 73 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 75 61 63 62 79 70 70 73 2e 70 64 62 } //3 source\repos\uacbypps\x64\Release\uacbypps.pdb
		$a_00_1 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 43 00 6c 00 61 00 73 00 73 00 65 00 73 00 5c 00 6d 00 73 00 2d 00 73 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 5c 00 53 00 68 00 65 00 6c 00 6c 00 5c 00 4f 00 70 00 65 00 6e 00 5c 00 63 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 } //1 Software\Classes\ms-settings\Shell\Open\command
		$a_00_2 = {45 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 } //1 EncryptedCommand
		$a_00_3 = {44 00 65 00 6c 00 65 00 67 00 61 00 74 00 65 00 45 00 78 00 65 00 63 00 75 00 74 00 65 00 } //1 DelegateExecute
		$a_01_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
		$a_00_5 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 33 00 32 00 5c 00 66 00 6f 00 64 00 68 00 65 00 6c 00 70 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 Windows\System32\fodhelper.exe
	condition:
		((#a_01_0  & 1)*3+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_01_4  & 1)*1+(#a_00_5  & 1)*1) >=8
 
}