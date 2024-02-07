
rule TrojanDropper_Win32_Small_ALH{
	meta:
		description = "TrojanDropper:Win32/Small.ALH,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 75 74 6f 6c 69 76 65 2e 73 79 73 } //01 00  autolive.sys
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 53 53 65 61 72 63 68 } //01 00  Software\Microsoft\SSearch
		$a_01_2 = {25 73 5c 52 75 6e 64 6c 6c 33 32 2e 65 78 65 20 22 25 73 5c 25 73 22 2c 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } //01 00  %s\Rundll32.exe "%s\%s",DllCanUnloadNow
		$a_01_3 = {72 65 67 73 76 72 33 32 20 2f 75 20 2f 73 20 25 73 5c 49 6e 74 65 53 65 61 72 63 68 2e 64 6c 6c } //01 00  regsvr32 /u /s %s\InteSearch.dll
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 53 53 65 61 72 63 68 5c 55 70 64 61 74 65 } //01 00  Software\Microsoft\SSearch\Update
		$a_01_5 = {73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 25 73 2e 73 79 73 } //00 00  system32\drivers\%s.sys
	condition:
		any of ($a_*)
 
}