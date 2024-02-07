
rule Trojan_Win32_NukeSped_RS_MSR{
	meta:
		description = "Trojan:Win32/NukeSped.RS!MSR,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {56 69 72 74 75 61 6c 46 72 65 65 } //01 00  VirtualFree
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //01 00  VirtualAlloc
		$a_01_2 = {57 53 32 5f 33 32 2e 64 6c 6c } //01 00  WS2_32.dll
		$a_01_3 = {57 72 69 74 65 46 69 6c 65 } //01 00  WriteFile
		$a_01_4 = {43 72 65 61 74 65 54 68 72 65 61 64 } //01 00  CreateThread
		$a_01_5 = {43 52 59 50 54 33 32 2e 44 4c 4c } //01 00  CRYPT32.DLL
		$a_00_6 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 6d 00 74 00 68 00 6a 00 6b 00 } //00 00  Software\mthjk
	condition:
		any of ($a_*)
 
}