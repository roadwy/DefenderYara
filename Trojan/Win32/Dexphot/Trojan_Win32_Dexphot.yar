
rule Trojan_Win32_Dexphot{
	meta:
		description = "Trojan:Win32/Dexphot,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 38 50 45 00 00 74 0f b8 90 01 04 e8 90 01 04 e9 90 01 04 8b 45 90 01 01 50 68 00 20 00 00 8b 45 90 01 01 8b 40 50 50 8b 45 90 01 01 8b 40 34 50 6a ff e8 90 00 } //01 00 
		$a_03_1 = {30 02 81 3d 90 01 08 77 90 01 01 81 3d 90 01 08 72 90 01 01 33 c9 b2 01 a1 90 09 1d 00 a0 90 01 04 02 05 90 01 04 02 05 90 01 04 8b 15 90 01 04 03 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Dexphot_2{
	meta:
		description = "Trojan:Win32/Dexphot,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 49 43 34 00 00 00 00 41 49 43 35 00 00 00 00 41 49 43 36 00 00 00 00 ff ff ff ff 10 00 00 00 25 73 25 73 25 73 25 73 25 73 25 73 25 73 25 73 00 00 00 00 41 49 43 37 00 00 00 00 41 49 43 38 00 00 00 00 41 49 43 39 00 00 00 00 41 49 43 39 2e 6c 6f 6f 70 00 } //01 00 
		$a_01_1 = {62 00 00 00 ff ff ff ff 01 00 00 00 69 00 00 00 ff ff ff ff 01 00 00 00 6e 00 00 00 ff ff ff ff 01 00 00 00 2e 00 00 00 ff ff ff ff 01 00 00 00 64 00 00 00 ff ff ff ff 01 00 00 00 61 00 00 00 ff ff ff ff 01 00 00 00 74 00 } //01 00 
		$a_03_2 = {66 81 38 4d 5a 0f 85 90 01 04 33 c0 90 00 } //01 00 
		$a_03_3 = {50 68 00 20 00 00 8b 45 90 01 01 8b 40 50 50 8b 45 90 01 01 8b 40 34 50 90 03 02 00 6a ff e8 90 01 04 89 45 90 00 } //01 00 
		$a_03_4 = {8b 00 83 78 28 00 0f 84 90 01 04 33 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Dexphot_3{
	meta:
		description = "Trojan:Win32/Dexphot,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {2e 00 48 00 65 00 61 00 64 00 65 00 72 00 73 00 5b 00 27 00 55 00 73 00 65 00 72 00 2d 00 41 00 67 00 65 00 6e 00 74 00 27 00 5d 00 20 00 3d 00 20 00 27 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 72 00 27 00 } //01 00  .Headers['User-Agent'] = 'Windows Installer'
		$a_00_1 = {2e 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 46 00 69 00 6c 00 65 00 28 00 27 00 68 00 74 00 74 00 70 00 } //01 00  .DownloadFile('http
		$a_00_2 = {2e 00 69 00 6e 00 66 00 6f 00 2f 00 } //01 00  .info/
		$a_00_3 = {53 00 74 00 61 00 72 00 74 00 2d 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 } //01 00  Start-Process 
		$a_00_4 = {2d 00 41 00 72 00 67 00 75 00 6d 00 65 00 6e 00 74 00 4c 00 69 00 73 00 74 00 20 00 27 00 2f 00 71 00 } //00 00  -ArgumentList '/q
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Dexphot_4{
	meta:
		description = "Trojan:Win32/Dexphot,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {6f 63 65 73 73 4d 64 69 6e 6f 63 65 73 73 4d 69 64 73 73 4d 69 6e 69 6e 6f 63 65 73 73 4d 69 6e 64 6f 63 65 73 73 4d 69 6e 69 6e 6f 63 65 73 73 4d 69 6e 69 6e } //00 00  ocessMdinocessMidssMininocessMindocessMininocessMinin
	condition:
		any of ($a_*)
 
}