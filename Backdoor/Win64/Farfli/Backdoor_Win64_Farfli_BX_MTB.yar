
rule Backdoor_Win64_Farfli_BX_MTB{
	meta:
		description = "Backdoor:Win64/Farfli.BX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {37 7a 7a 2e 65 78 65 } //01 00  7zz.exe
		$a_01_1 = {5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 33 36 30 2e 64 6c 6c } //01 00  \ProgramData\360.dll
		$a_01_2 = {50 72 6f 67 72 61 6d 44 61 74 61 5c 72 75 6e 64 6c 6c 33 32 32 32 2e 65 78 65 } //01 00  ProgramData\rundll3222.exe
		$a_01_3 = {5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 73 76 63 68 6f 73 74 2e 74 78 74 } //01 00  \ProgramData\svchost.txt
		$a_01_4 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //01 00  VirtualAlloc
		$a_01_5 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 } //01 00  URLDownloadToFile
		$a_01_6 = {53 68 65 6c 6c 45 78 65 63 75 74 65 } //00 00  ShellExecute
	condition:
		any of ($a_*)
 
}