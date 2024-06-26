
rule Trojan_Win32_Inject_AK{
	meta:
		description = "Trojan:Win32/Inject.AK,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 09 00 00 05 00 "
		
	strings :
		$a_00_0 = {5c 69 6e 6a 65 63 74 5c 72 65 6c 65 61 73 65 5c } //03 00  \inject\release\
		$a_00_1 = {77 69 6e 6d 6d 36 34 2e 64 6c 6c } //03 00  winmm64.dll
		$a_00_2 = {25 73 5c 4b 42 25 64 2e 6c 6f 67 } //01 00  %s\KB%d.log
		$a_00_3 = {5c 4e 6f 74 69 66 79 5c 57 69 6e 6c 6f 67 6f 6e } //01 00  \Notify\Winlogon
		$a_00_4 = {5c 53 68 65 6c 6c 53 65 72 76 69 63 65 4f 62 6a 65 63 74 44 65 6c 61 79 4c 6f 61 64 } //01 00  \ShellServiceObjectDelayLoad
		$a_02_5 = {45 54 20 2f 90 01 01 2e 70 68 70 3f 90 00 } //01 00 
		$a_00_6 = {6f 73 74 3a 20 77 77 77 2e 67 6f 6f 67 6c 65 2e } //01 00  ost: www.google.
		$a_00_7 = {6f 73 74 3a 20 77 77 77 2e 62 69 6e 67 2e } //01 00  ost: www.bing.
		$a_00_8 = {66 69 72 65 66 6f 78 2e 65 78 65 } //00 00  firefox.exe
	condition:
		any of ($a_*)
 
}