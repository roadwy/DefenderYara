
rule Trojan_Win32_Vidar_GEV_MTB{
	meta:
		description = "Trojan:Win32/Vidar.GEV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 2e 6d 65 2f 6e 6f 6b 74 61 73 69 6e 61 } //01 00  t.me/noktasina
		$a_01_1 = {39 35 2e 32 31 37 2e 31 35 32 2e 38 37 } //01 00  95.217.152.87
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 43 72 79 70 74 6f 67 72 61 70 68 79 } //01 00  SOFTWARE\Microsoft\Cryptography
		$a_80_3 = {53 65 6c 65 63 74 20 2a 20 46 72 6f 6d 20 41 6e 74 69 56 69 72 75 73 50 72 6f 64 75 63 74 } //Select * From AntiVirusProduct  01 00 
		$a_80_4 = {53 65 6c 65 63 74 20 2a 20 46 72 6f 6d 20 57 69 6e 33 32 5f 4f 70 65 72 61 74 69 6e 67 53 79 73 74 65 6d } //Select * From Win32_OperatingSystem  01 00 
		$a_01_5 = {45 78 6f 64 75 73 5c 65 78 6f 64 75 73 2e 77 61 6c 6c 65 74 } //01 00  Exodus\exodus.wallet
		$a_01_6 = {5c 44 6f 77 6e 6c 6f 61 64 73 5c 25 73 5f 25 73 2e 74 78 74 } //01 00  \Downloads\%s_%s.txt
		$a_01_7 = {5c 73 63 72 65 65 6e 73 68 6f 74 2e 6a 70 67 } //01 00  \screenshot.jpg
		$a_01_8 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //00 00  VirtualProtect
	condition:
		any of ($a_*)
 
}