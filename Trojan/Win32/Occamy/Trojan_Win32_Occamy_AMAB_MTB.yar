
rule Trojan_Win32_Occamy_AMAB_MTB{
	meta:
		description = "Trojan:Win32/Occamy.AMAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {43 3a 5c 54 45 4d 50 5c 32 38 39 30 2e 74 6d 70 5c 31 2e 62 61 74 } //01 00  C:\TEMP\2890.tmp\1.bat
		$a_81_1 = {43 3a 5c 54 45 4d 50 5c 32 38 39 31 2e 74 6d 70 } //01 00  C:\TEMP\2891.tmp
		$a_81_2 = {25 74 65 6d 70 25 5c 70 6f 70 75 70 2e 73 65 64 } //01 00  %temp%\popup.sed
		$a_81_3 = {65 78 74 64 2e 65 78 65 } //01 00  extd.exe
		$a_81_4 = {73 65 74 20 70 70 6f 70 75 70 5f 65 78 65 63 75 74 61 62 6c 65 3d 70 6f 70 75 70 65 2e 65 78 65 } //00 00  set ppopup_executable=popupe.exe
	condition:
		any of ($a_*)
 
}