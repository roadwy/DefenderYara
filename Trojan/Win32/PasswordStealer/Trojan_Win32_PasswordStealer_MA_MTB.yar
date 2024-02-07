
rule Trojan_Win32_PasswordStealer_MA_MTB{
	meta:
		description = "Trojan:Win32/PasswordStealer.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 65 6c 4e 6f 64 65 52 75 6e 44 4c 4c 33 32 } //01 00  DelNodeRunDLL32
		$a_01_1 = {54 45 4d 50 5c 49 58 50 30 30 30 2e 54 4d 50 } //01 00  TEMP\IXP000.TMP
		$a_01_2 = {52 65 62 6f 6f 74 } //01 00  Reboot
		$a_01_3 = {44 65 63 72 79 70 74 46 69 6c 65 41 } //01 00  DecryptFileA
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 } //01 00  Software\Microsoft\Windows\CurrentVersion\RunOnce
		$a_01_5 = {53 6c 65 65 70 } //01 00  Sleep
		$a_01_6 = {58 00 6d 00 68 00 6e 00 6b 00 63 00 71 00 6f 00 69 00 } //01 00  Xmhnkcqoi
		$a_01_7 = {4b 00 63 00 73 00 73 00 79 00 6b 00 61 00 } //00 00  Kcssyka
	condition:
		any of ($a_*)
 
}