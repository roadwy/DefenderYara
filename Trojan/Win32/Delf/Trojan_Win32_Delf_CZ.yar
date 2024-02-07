
rule Trojan_Win32_Delf_CZ{
	meta:
		description = "Trojan:Win32/Delf.CZ,SIGNATURE_TYPE_PEHSTR_EXT,2c 00 2c 00 0a 00 00 0a 00 "
		
	strings :
		$a_00_0 = {53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 41 } //0a 00  SetWindowsHookExA
		$a_00_1 = {5c 74 65 6d 70 73 5c 73 76 63 68 6f 73 74 2e 65 78 65 } //0a 00  \temps\svchost.exe
		$a_00_2 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //0a 00  SOFTWARE\Borland\Delphi\RTL
		$a_02_3 = {68 74 74 70 3a 2f 2f 90 02 15 2e 63 6e 2f 90 00 } //01 00 
		$a_02_4 = {0a 64 65 6c 90 02 04 22 25 73 90 00 } //01 00 
		$a_02_5 = {0a 64 65 6c 90 02 04 25 30 90 00 } //01 00 
		$a_02_6 = {0a 64 65 6c 90 02 04 22 43 3a 5c 6d 79 61 70 70 2e 65 78 65 90 00 } //01 00 
		$a_00_7 = {56 4d 50 72 6f 74 65 63 74 } //01 00  VMProtect
		$a_00_8 = {54 4d 65 73 73 61 67 65 72 } //01 00  TMessager
		$a_00_9 = {53 65 72 76 69 63 65 53 74 6f 70 } //00 00  ServiceStop
	condition:
		any of ($a_*)
 
}