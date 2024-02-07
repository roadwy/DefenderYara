
rule Trojan_Win32_Susav_A{
	meta:
		description = "Trojan:Win32/Susav.A,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {45 6e 75 6d 57 69 6e 64 6f 77 73 } //01 00  EnumWindows
		$a_01_1 = {47 65 74 43 6c 61 73 73 4e 61 6d 65 41 } //01 00  GetClassNameA
		$a_01_2 = {8b 85 c0 fe ff ff 3d 41 56 50 2e 75 02 } //01 00 
		$a_01_3 = {41 64 6a 75 73 74 54 6f 6b 65 6e 50 72 69 76 69 6c 65 67 65 73 } //01 00  AdjustTokenPrivileges
		$a_01_4 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //00 00  WriteProcessMemory
	condition:
		any of ($a_*)
 
}