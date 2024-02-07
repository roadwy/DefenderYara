
rule Trojan_Win32_Pernefed{
	meta:
		description = "Trojan:Win32/Pernefed,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //01 00  SOFTWARE\Borland\Delphi\RTL
		$a_02_1 = {50 44 32 30 90 01 02 4d 6f 6e 69 74 6f 72 00 00 00 70 64 2e 64 6c 6c 90 00 } //01 00 
		$a_00_2 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 70 64 2e 64 6c 6c } //00 00  C:\WINDOWS\pd.dll
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Pernefed_2{
	meta:
		description = "Trojan:Win32/Pernefed,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {c6 03 2f c6 43 01 71 c6 43 02 0d c6 43 03 0a c6 43 04 69 c6 43 05 66 c6 43 06 20 c6 43 07 65 c6 43 08 78 } //02 00 
		$a_03_1 = {8a 54 3a ff 80 f2 ff e8 90 01 04 8b 55 f8 8b c6 e8 90 01 04 47 4b 75 e0 90 00 } //01 00 
		$a_01_2 = {72 75 6e 6d 61 78 00 } //01 00 
		$a_01_3 = {72 75 6e 6d 69 6e 00 } //01 00 
		$a_03_4 = {50 00 44 00 32 00 30 00 90 01 04 4d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Pernefed_3{
	meta:
		description = "Trojan:Win32/Pernefed,SIGNATURE_TYPE_PEHSTR_EXT,66 00 66 00 03 00 00 64 00 "
		
	strings :
		$a_02_0 = {55 8b ec 83 c4 f0 b8 90 01 02 50 00 e8 90 01 02 ef ff 68 90 01 02 50 00 e8 90 01 02 ef ff 8b 15 90 01 02 51 00 89 02 68 90 01 02 50 00 6a 00 6a 00 e8 90 01 02 ef ff 85 c0 79 05 90 00 } //01 00 
		$a_00_1 = {ff ff ff ff 10 00 00 00 46 6f 75 6e 64 20 74 68 72 65 61 74 73 3a 20 30 00 } //01 00 
		$a_00_2 = {ff ff ff ff 15 00 00 00 53 74 61 74 75 73 3a 20 53 63 61 6e 6e 69 6e 67 20 66 69 6c 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Pernefed_4{
	meta:
		description = "Trojan:Win32/Pernefed,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 0a 00 "
		
	strings :
		$a_00_0 = {53 4f 46 54 57 41 52 45 5c 42 6f 72 6c 61 6e 64 5c 44 65 6c 70 68 69 5c 52 54 4c } //01 00  SOFTWARE\Borland\Delphi\RTL
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 50 44 65 66 65 6e 64 65 72 } //01 00  SOFTWARE\Microsoft\PDefender
		$a_01_2 = {50 65 72 66 65 63 74 20 44 65 66 65 6e 64 65 72 } //01 00  Perfect Defender
		$a_00_3 = {53 6f 66 74 57 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //00 00  SoftWare\Microsoft\Windows\CurrentVersion\Run
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Pernefed_5{
	meta:
		description = "Trojan:Win32/Pernefed,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 09 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 54 3a ff 80 f2 ff e8 90 01 04 8b 55 f8 8b c6 e8 90 01 04 47 4b 75 e0 90 00 } //01 00 
		$a_03_1 = {8a 54 0a ff 80 f2 ff e8 90 01 04 8b 55 90 01 01 8b 45 90 01 01 e8 90 01 04 8b 45 90 01 01 ff 45 90 01 01 ff 4d 90 01 01 75 d5 90 00 } //01 00 
		$a_03_2 = {8a 54 38 ff 8a 04 1e e8 90 01 04 88 04 1e 8b 45 fc 8a 44 38 ff 30 04 1e 43 ff 4d 90 01 01 75 de 90 00 } //01 00 
		$a_01_3 = {8f 9b 99 91 9b 8d 00 } //01 00 
		$a_01_4 = {8f 9b 92 90 91 96 8b 90 8d 00 } //01 00 
		$a_01_5 = {bb 9a 99 9a 91 9b 9a 8d } //01 00 
		$a_01_6 = {cc e0 db ff ff ff dd eb e6 78 ad 9f 02 63 4e 02 6e 3d 02 7c 26 24 8e 42 ff ff ff ff ff ff 24 76 } //02 00 
		$a_01_7 = {2d 16 01 00 00 48 50 8b 45 90 01 01 2d 5e 01 00 00 90 09 11 00 6a 00 6a 30 e8 90 01 04 68 00 00 40 00 8b 45 90 01 01 90 00 } //02 00 
		$a_01_8 = {8a 45 08 2c 01 72 77 0f 84 99 00 00 00 fe c8 74 09 fe c8 74 39 e9 b2 00 00 00 ba } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Pernefed_6{
	meta:
		description = "Trojan:Win32/Pernefed,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 02 00 "
		
	strings :
		$a_02_0 = {53 63 68 74 61 73 6b 73 2e 65 78 65 20 2f 44 65 6c 65 74 65 20 90 03 00 03 2f 46 20 2f 54 4e 20 22 44 65 66 65 6e 64 65 72 20 4d 6f 6e 69 74 6f 72 22 90 00 } //01 00 
		$a_03_1 = {59 6f 75 20 61 72 65 20 6e 6f 77 20 72 65 61 64 79 20 74 6f 20 75 6e 69 6e 73 74 61 6c 6c 20 74 68 65 20 50 65 72 66 65 63 74 20 44 65 66 65 6e 64 65 72 20 32 30 90 01 02 20 66 72 6f 6d 20 79 6f 75 72 20 73 79 73 74 65 6d 2e 90 00 } //02 00 
		$a_03_2 = {64 65 6c 65 74 65 64 2e 2e 2e 00 90 02 0c 63 61 6e 27 74 20 64 65 6c 65 74 65 20 50 65 72 66 65 63 74 20 44 65 66 65 6e 64 65 72 20 32 30 90 01 02 20 6b 65 79 73 2e 2e 2e 90 00 } //01 00 
		$a_01_3 = {55 6e 69 6e 73 74 61 6c 6c 5c 50 44 65 66 65 6e 64 65 72 } //01 00  Uninstall\PDefender
		$a_01_4 = {4d 69 63 72 6f 73 6f 66 74 5c 50 44 65 66 65 6e 64 65 72 } //01 00  Microsoft\PDefender
		$a_03_5 = {20 74 6f 20 63 6f 6d 70 6c 65 74 65 6c 79 20 72 65 6d 6f 76 65 20 50 65 72 66 65 63 74 20 44 65 66 65 6e 64 65 72 2e 00 90 02 08 5c 70 64 6d 6f 6e 69 74 6f 72 2e 65 78 65 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Pernefed_7{
	meta:
		description = "Trojan:Win32/Pernefed,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 0b 00 00 02 00 "
		
	strings :
		$a_03_0 = {8a 54 3a ff 80 f2 ff e8 90 01 04 8b 55 f8 8b c6 e8 90 01 04 47 4b 75 e0 90 00 } //02 00 
		$a_00_1 = {53 63 68 74 61 73 6b 73 2e 65 78 65 20 2f 63 72 65 61 74 65 20 2f 74 6e 20 22 44 65 66 65 6e 64 65 72 20 4d 6f 6e 69 74 6f 72 22 } //01 00  Schtasks.exe /create /tn "Defender Monitor"
		$a_00_2 = {2f 75 70 64 61 74 65 2e 70 68 70 3f 62 3d 00 } //01 00 
		$a_00_3 = {41 66 74 65 72 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 20 73 74 61 72 74 65 64 20 75 70 2c 20 72 75 6e 20 49 6e 73 74 61 6c 61 74 69 6f 6e 20 61 67 61 69 6e 2e } //01 00  After your computer started up, run Instalation again.
		$a_00_4 = {50 65 72 66 65 63 74 20 44 65 66 65 6e 64 65 72 20 32 30 30 } //02 00  Perfect Defender 200
		$a_03_5 = {8a 54 0a ff 80 f2 ff e8 90 01 04 8b 55 90 01 01 8b 45 90 01 01 e8 90 01 04 8b 45 90 01 01 ff 45 90 01 01 ff 4d 90 01 01 75 90 00 } //02 00 
		$a_01_6 = {50 44 32 30 30 39 53 68 75 74 74 69 6e 67 00 } //01 00 
		$a_00_7 = {2f 75 70 64 31 2e 70 68 70 3f 00 } //02 00 
		$a_01_8 = {66 72 6d 50 44 32 30 30 39 41 6c 65 72 74 00 } //01 00 
		$a_00_9 = {46 69 72 65 77 61 6c 6c 20 41 6c 65 72 74 00 } //01 00 
		$a_00_10 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 50 44 65 66 65 6e 64 65 72 } //00 00  SOFTWARE\Microsoft\PDefender
	condition:
		any of ($a_*)
 
}