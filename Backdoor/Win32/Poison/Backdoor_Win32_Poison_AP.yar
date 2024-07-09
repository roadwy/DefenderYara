
rule Backdoor_Win32_Poison_AP{
	meta:
		description = "Backdoor:Win32/Poison.AP,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_02_0 = {81 c4 0c 02 00 00 c3 [0-04] 56 8b 35 ?? ?? ?? ?? 68 7f 96 98 00 ff d6 eb f7 } //1
		$a_00_1 = {4c 6f 63 61 6c 20 41 70 70 57 69 7a 61 72 64 2d 47 65 6e 65 72 61 74 65 64 20 41 70 70 6c 69 63 61 74 69 6f 6e 73 } //1 Local AppWizard-Generated Applications
		$a_00_2 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 54 63 70 69 70 5c 50 61 72 61 6d 65 74 65 72 73 5c 49 6e 74 65 72 66 61 63 65 73 } //1 SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces
		$a_00_3 = {6a 0c 6a 35 6a 2b 6a 0c c7 45 e8 2b 00 00 00 c7 45 e4 35 00 00 00 e8 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}