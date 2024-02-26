
rule Trojan_Win32_Zusy_DV_MTB{
	meta:
		description = "Trojan:Win32/Zusy.DV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 3a 2f 2f 25 73 3a 25 64 2f 25 73 2f 25 73 } //01 00  http://%s:%d/%s/%s
		$a_81_1 = {25 73 25 2e 38 78 2e 62 61 74 } //01 00  %s%.8x.bat
		$a_81_2 = {69 66 20 65 78 69 73 74 20 22 25 73 22 20 67 6f 74 6f 20 3a 44 45 4c 46 49 4c 45 } //01 00  if exist "%s" goto :DELFILE
		$a_81_3 = {53 4f 46 54 57 41 52 45 5c 47 54 70 6c 75 73 } //01 00  SOFTWARE\GTplus
		$a_81_4 = {25 73 20 4d 20 25 73 20 2d 72 20 2d 6f 2b 20 2d 65 70 31 20 22 25 73 22 20 22 25 73 5c 2a 22 } //01 00  %s M %s -r -o+ -ep1 "%s" "%s\*"
		$a_81_5 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //01 00  URLDownloadToFileA
		$a_81_6 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //00 00  ShellExecuteA
	condition:
		any of ($a_*)
 
}