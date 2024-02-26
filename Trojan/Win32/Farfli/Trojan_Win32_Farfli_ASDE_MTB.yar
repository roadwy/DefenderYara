
rule Trojan_Win32_Farfli_ASDE_MTB{
	meta:
		description = "Trojan:Win32/Farfli.ASDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 4d ec 8a 1c 08 80 c3 90 01 01 88 1c 08 8b 4d ec 8a 1c 08 80 f3 90 01 01 88 1c 08 40 3b c2 7c 90 00 } //01 00 
		$a_01_1 = {c6 44 24 18 43 c6 44 24 19 72 c6 44 24 1b 61 88 4c 24 1c c6 44 24 1e 45 c6 44 24 1f 76 c6 44 24 21 6e 88 4c 24 22 c6 44 24 23 41 88 5c 24 24 ff 15 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Farfli_ASDE_MTB_2{
	meta:
		description = "Trojan:Win32/Farfli.ASDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 75 63 6b 79 6f 75 } //02 00  fuckyou
		$a_01_1 = {50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 43 6f 6d 6d 6f 6e 20 46 69 6c 65 73 5c 73 63 76 68 6f 73 74 2e 65 78 65 } //01 00  Program Files\Common Files\scvhost.exe
		$a_01_2 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 72 75 6e 64 6c 6c 33 32 2e 65 78 65 } //01 00  taskkill /f /im rundll32.exe
		$a_01_3 = {47 68 30 73 74 20 52 41 54 } //02 00  Gh0st RAT
		$a_01_4 = {4b 37 c9 b1 b6 be 00 00 4b 37 54 53 65 63 75 72 69 74 79 2e 65 78 65 00 43 4d 43 c9 b1 b6 be 00 43 4d 43 54 72 61 79 49 63 6f 6e 2e 65 78 65 00 46 2d 50 52 4f 54 c9 b1 b6 be 00 00 46 2d 50 52 4f 54 2e 45 58 45 00 00 43 6f 72 61 6e 74 69 32 30 31 32 c9 b1 b6 be 00 43 6f 72 61 6e 74 69 43 6f 6e 74 72 6f 6c 43 65 6e 74 65 72 33 32 2e 65 78 65 } //02 00 
		$a_01_5 = {5b 50 61 75 73 65 20 42 72 65 61 6b 5d 00 00 00 5b 53 68 69 66 74 5d 00 5b 41 6c 74 5d 00 00 00 5b 43 4c 45 41 52 5d 00 5b 42 41 43 4b 53 50 41 43 45 5d 00 5b 44 45 4c 45 54 45 5d 00 00 00 00 5b 49 4e 53 45 52 54 5d } //00 00 
	condition:
		any of ($a_*)
 
}