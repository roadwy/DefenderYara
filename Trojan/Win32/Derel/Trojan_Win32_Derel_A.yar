
rule Trojan_Win32_Derel_A{
	meta:
		description = "Trojan:Win32/Derel.A,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 06 00 00 0a 00 "
		
	strings :
		$a_00_0 = {2f 00 68 00 61 00 72 00 6d 00 6f 00 6e 00 79 00 7a 00 7a 00 2f 00 70 00 61 00 67 00 65 00 73 00 2f 00 66 00 75 00 6c 00 6c 00 6a 00 75 00 73 00 74 00 75 00 6e 00 68 00 6f 00 6f 00 6b 00 2e 00 70 00 68 00 70 00 } //0a 00  /harmonyzz/pages/fulljustunhook.php
		$a_00_1 = {2f 00 68 00 61 00 72 00 6d 00 6f 00 6e 00 79 00 7a 00 7a 00 2f 00 61 00 70 00 69 00 2e 00 70 00 68 00 70 00 } //01 00  /harmonyzz/api.php
		$a_01_2 = {57 6f 77 36 34 44 69 73 61 62 6c 65 57 6f 77 36 34 46 73 52 65 64 69 72 65 63 74 69 6f 6e } //01 00  Wow64DisableWow64FsRedirection
		$a_01_3 = {73 74 6f 70 20 56 53 53 } //01 00  stop VSS
		$a_00_4 = {64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 61 00 6c 00 6c 00 20 00 2f 00 71 00 75 00 69 00 65 00 74 00 } //03 00  delete shadows /all /quiet
		$a_02_5 = {c7 05 00 62 40 00 01 00 00 00 66 8b 90 01 03 40 00 66 89 90 01 01 c0 8d 90 01 01 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}