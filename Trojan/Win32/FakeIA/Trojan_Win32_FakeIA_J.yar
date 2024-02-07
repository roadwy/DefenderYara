
rule Trojan_Win32_FakeIA_J{
	meta:
		description = "Trojan:Win32/FakeIA.J,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {41 50 50 44 41 54 41 5c 90 01 0a 2e 67 69 66 90 00 } //01 00 
		$a_01_1 = {c3 90 72 00 65 00 61 00 6c 00 74 00 65 00 6b 00 73 00 } //01 00 
		$a_01_2 = {77 00 69 00 6e 00 6c 00 6f 00 67 00 6f 00 6e 00 73 00 2e 00 65 00 78 00 65 00 } //01 00  winlogons.exe
		$a_00_3 = {5a 77 51 75 65 72 79 53 79 73 74 65 6d 49 6e 66 6f 72 6d 61 74 69 6f 6e } //00 00  ZwQuerySystemInformation
	condition:
		any of ($a_*)
 
}