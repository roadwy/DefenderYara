
rule TrojanDropper_Win32_Wlock_A{
	meta:
		description = "TrojanDropper:Win32/Wlock.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {24 01 3c 01 74 04 d2 0b eb 02 d2 03 8a 85 90 01 02 ff ff 30 03 90 00 } //02 00 
		$a_03_1 = {c6 41 05 ff 8b 95 90 01 02 ff ff 03 95 90 01 02 ff ff c6 42 06 e3 c7 85 90 01 02 ff ff 00 00 00 00 90 00 } //01 00 
		$a_00_2 = {2f 76 20 77 6c 6f 63 6b 5f 64 65 6c 20 2f 74 20 52 45 47 5f 53 5a 20 2f 64 20 22 63 6d 64 20 2f 63 20 64 65 6c } //01 00  /v wlock_del /t REG_SZ /d "cmd /c del
		$a_00_3 = {5c 57 69 6e 6c 6f 67 6f 6e 22 20 2f 76 20 55 73 65 72 69 6e 69 74 20 2f 74 20 52 45 47 5f 53 5a 20 2f 64 20 22 25 57 49 4e 44 49 52 25 } //00 00  \Winlogon" /v Userinit /t REG_SZ /d "%WINDIR%
	condition:
		any of ($a_*)
 
}