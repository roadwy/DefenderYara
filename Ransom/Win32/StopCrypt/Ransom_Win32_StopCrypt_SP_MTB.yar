
rule Ransom_Win32_StopCrypt_SP_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 43 00 20 00 70 00 69 00 6e 00 67 00 20 00 31 00 2e 00 31 00 2e 00 31 00 2e 00 31 00 20 00 2d 00 6e 00 20 00 33 00 20 00 2d 00 77 00 20 00 33 00 30 00 30 00 30 00 20 00 3e 00 20 00 4e 00 75 00 6c 00 20 00 26 00 20 00 44 00 65 00 6c 00 20 00 2f 00 66 00 20 00 2f 00 71 00 20 00 22 00 25 00 73 00 22 00 } //02 00  cmd.exe /C ping 1.1.1.1 -n 3 -w 3000 > Nul & Del /f /q "%s"
		$a_01_1 = {74 65 73 74 65 72 73 2e 65 78 65 } //02 00  testers.exe
		$a_01_2 = {41 6c 6c 69 65 20 64 65 74 65 63 74 65 64 } //02 00  Allie detected
		$a_01_3 = {41 55 33 21 } //00 00  AU3!
	condition:
		any of ($a_*)
 
}
rule Ransom_Win32_StopCrypt_SP_MTB_2{
	meta:
		description = "Ransom:Win32/StopCrypt.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 39 8b f0 81 e6 90 01 04 33 f7 c1 e8 08 8b 34 b5 90 01 04 33 c6 41 4a 75 e3 90 00 } //01 00 
		$a_00_1 = {49 00 6e 00 66 00 65 00 63 00 74 00 65 00 64 00 20 00 77 00 69 00 74 00 68 00 20 00 61 00 20 00 76 00 69 00 72 00 6f 00 75 00 73 00 } //01 00  Infected with a virous
		$a_00_2 = {69 00 6e 00 66 00 6f 00 2e 00 74 00 78 00 74 00 } //01 00  info.txt
		$a_00_3 = {77 00 62 00 61 00 64 00 6d 00 69 00 6e 00 20 00 64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 79 00 73 00 74 00 65 00 6d 00 73 00 74 00 61 00 74 00 65 00 62 00 61 00 63 00 6b 00 75 00 70 00 } //00 00  wbadmin delete systemstatebackup
	condition:
		any of ($a_*)
 
}