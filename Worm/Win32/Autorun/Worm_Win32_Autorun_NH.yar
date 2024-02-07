
rule Worm_Win32_Autorun_NH{
	meta:
		description = "Worm:Win32/Autorun.NH,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {3a 5c 61 75 74 6f 72 75 6e 2e 69 6e 66 00 00 00 ff ff ff ff 90 01 04 5b 61 75 74 6f 72 75 6e 5d 90 00 } //01 00 
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {55 53 42 7c 49 6e 66 65 63 74 65 64 20 44 72 69 76 65 } //01 00  USB|Infected Drive
		$a_00_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //00 00  URLDownloadToFileA
	condition:
		any of ($a_*)
 
}