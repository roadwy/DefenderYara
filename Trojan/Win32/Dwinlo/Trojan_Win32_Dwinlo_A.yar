
rule Trojan_Win32_Dwinlo_A{
	meta:
		description = "Trojan:Win32/Dwinlo.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 8a 44 18 ff 24 0f 8b 55 f0 8a 54 32 ff 80 e2 0f 32 c2 88 45 f7 8d 45 fc e8 } //02 00 
		$a_01_1 = {34 35 36 37 38 39 8b c0 7e 61 62 63 64 65 66 67 } //01 00 
		$a_01_2 = {2f 76 20 77 69 6e 6c 6f 61 64 20 2f 64 } //01 00  /v winload /d
		$a_01_3 = {2e 65 78 65 22 20 2f 66 00 } //01 00 
		$a_01_4 = {72 65 67 20 61 64 64 20 48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 } //00 00  reg add HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce
	condition:
		any of ($a_*)
 
}