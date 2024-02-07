
rule Backdoor_Win32_Phorpiex_J{
	meta:
		description = "Backdoor:Win32/Phorpiex.J,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 07 00 00 14 00 "
		
	strings :
		$a_03_0 = {51 8b c1 b9 08 00 00 00 8b d0 83 e2 01 75 04 d1 e8 eb 07 d1 e8 35 90 01 04 e2 ec ab 59 41 81 f9 00 01 00 00 72 d9 8b 75 08 8b 7d 0c 33 c9 bb ff ff ff ff 51 33 c0 ac 8b d3 c1 eb 08 53 87 d3 81 e3 ff 00 00 00 33 d8 93 b9 04 00 00 00 f7 e1 93 8b 90 01 02 03 c3 8b 00 5b 33 c3 8b d8 59 41 3b cf 72 d1 90 00 } //14 00 
		$a_03_1 = {b8 04 04 04 04 8d 7d 90 01 01 aa 83 7d 90 01 02 74 06 83 7d 90 01 02 75 90 01 01 8a 45 90 01 01 8d 7d 90 01 01 66 0f b6 c8 66 c1 e0 08 66 0b c1 aa eb 90 01 01 b8 01 01 01 01 8d 7d 90 01 01 aa 90 00 } //05 00 
		$a_00_2 = {39 32 2e 36 33 2e 31 39 37 2e 34 38 } //05 00  92.63.197.48
		$a_00_3 = {57 49 4e 44 4f 57 53 5c 54 2d 34 30 35 30 36 38 36 39 34 39 33 30 33 30 35 38 34 30 } //05 00  WINDOWS\T-405068694930305840
		$a_00_4 = {25 74 65 6d 70 25 5c 34 39 35 30 35 30 35 38 33 39 33 30 2e 65 78 65 26 73 74 61 72 74 20 25 74 65 6d 70 25 5c 34 39 35 30 35 30 35 38 33 39 33 30 2e 65 78 65 } //05 00  %temp%\495050583930.exe&start %temp%\495050583930.exe
		$a_00_5 = {50 6f 77 65 72 53 68 65 6c 6c 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 28 4e 65 77 2d 4f 62 6a 65 63 74 20 53 79 73 74 65 6d 2e 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 29 2e 44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //05 00  PowerShell -ExecutionPolicy Bypass (New-Object System.Net.WebClient).DownloadFile
		$a_00_6 = {62 69 74 73 61 64 6d 69 6e 20 2f 74 72 61 6e 73 66 65 72 20 67 65 74 69 74 6d 61 6e 20 2f 64 6f 77 6e 6c 6f 61 64 20 2f 70 72 69 6f 72 69 74 79 20 68 69 67 68 } //00 00  bitsadmin /transfer getitman /download /priority high
		$a_00_7 = {80 10 00 00 da 91 ee 92 0a f4 8d 86 c5 dc 2a } //65 00 
	condition:
		any of ($a_*)
 
}