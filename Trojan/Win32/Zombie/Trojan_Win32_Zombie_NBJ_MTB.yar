
rule Trojan_Win32_Zombie_NBJ_MTB{
	meta:
		description = "Trojan:Win32/Zombie.NBJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 c9 ff 8b f8 33 c0 f2 ae f7 d1 2b f9 8d 54 24 2c 8b c1 8b f7 8b fa c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4 } //01 00 
		$a_01_1 = {ff 15 e8 30 40 00 25 07 00 00 80 79 05 48 83 c8 f8 40 05 2e 14 00 00 89 44 24 60 8d 4c 24 64 } //01 00 
		$a_01_2 = {2f 63 20 64 65 6c } //01 00  /c del
		$a_01_3 = {43 4f 4d 53 50 45 43 } //01 00  COMSPEC
		$a_01_4 = {5f 2e 65 78 65 } //01 00  _.exe
		$a_01_5 = {5c 5a 6f 6d 62 69 65 2e 65 78 65 } //01 00  \Zombie.exe
		$a_01_6 = {57 49 4e 4e 54 } //01 00  WINNT
		$a_01_7 = {53 68 65 6c 6c 45 78 65 63 75 74 65 45 78 41 } //00 00  ShellExecuteExA
	condition:
		any of ($a_*)
 
}