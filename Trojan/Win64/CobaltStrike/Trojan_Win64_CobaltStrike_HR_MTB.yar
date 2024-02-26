
rule Trojan_Win64_CobaltStrike_HR_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.HR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  \Windows\CurrentVersion\Run
		$a_01_1 = {5c 6d 66 65 68 63 73 2e 65 78 65 } //01 00  \mfehcs.exe
		$a_01_2 = {63 6d 64 20 2f 63 20 74 61 73 6b 6b 69 6c 6c 20 2f 46 20 2f 50 49 44 } //01 00  cmd /c taskkill /F /PID
		$a_01_3 = {5c 4d 79 4e 65 77 44 4c 4c 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 70 64 68 2e 70 64 62 } //00 00  \MyNewDLL\x64\Release\pdh.pdb
	condition:
		any of ($a_*)
 
}