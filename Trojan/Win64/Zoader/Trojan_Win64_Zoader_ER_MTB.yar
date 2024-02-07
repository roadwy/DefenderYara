
rule Trojan_Win64_Zoader_ER_MTB{
	meta:
		description = "Trojan:Win64/Zoader.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 03 00 "
		
	strings :
		$a_81_0 = {2e 64 6c 6c 2c 44 65 6c 4e 6f 64 65 52 75 6e 44 4c 4c 33 32 } //03 00  .dll,DelNodeRunDLL32
		$a_81_1 = {53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 } //03 00  SeShutdownPrivilege
		$a_81_2 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 } //03 00  CurrentVersion\RunOnce
		$a_81_3 = {44 6f 49 6e 66 49 6e 73 74 61 6c 6c } //03 00  DoInfInstall
		$a_81_4 = {63 6d 64 20 2f 63 } //03 00  cmd /c
		$a_81_5 = {63 64 20 25 41 50 50 44 41 54 41 25 } //03 00  cd %APPDATA%
		$a_81_6 = {70 6f 77 65 72 73 68 65 6c 6c 20 49 6e 76 6f 6b 65 2d 57 65 62 52 65 71 75 65 73 74 20 } //00 00  powershell Invoke-WebRequest 
	condition:
		any of ($a_*)
 
}