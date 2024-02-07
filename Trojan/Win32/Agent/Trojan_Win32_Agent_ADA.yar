
rule Trojan_Win32_Agent_ADA{
	meta:
		description = "Trojan:Win32/Agent.ADA,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 52 4c 4d 4f 4e 2e 64 6c 6c 00 44 6f 57 6f 72 6b 00 49 6e 73 74 61 6c 6c 00 52 75 6e 4f 6e 63 65 00 55 6e 69 6e 73 74 61 6c 6c 00 57 53 50 53 74 61 72 74 75 70 00 } //01 00 
		$a_00_1 = {69 76 3d 25 6c 64 26 70 76 3d 25 6c 64 26 6c 67 3d 25 73 26 63 6f 3d 25 73 26 63 3d 25 6c 64 26 66 3d 25 73 26 69 3d 25 6c 64 26 73 63 3d 25 6c 64 26 73 6c 3d 25 6c 64 } //01 00  iv=%ld&pv=%ld&lg=%s&co=%s&c=%ld&f=%s&i=%ld&sc=%ld&sl=%ld
		$a_00_2 = {69 70 63 6f 6e 66 69 67 20 2f 72 65 6e 65 77 } //01 00  ipconfig /renew
		$a_01_3 = {4c 00 61 00 79 00 65 00 72 00 65 00 64 00 20 00 57 00 53 00 32 00 20 00 50 00 72 00 6f 00 76 00 69 00 64 00 65 00 72 00 } //01 00  Layered WS2 Provider
		$a_01_4 = {4c 00 61 00 79 00 65 00 72 00 65 00 64 00 20 00 48 00 69 00 64 00 64 00 65 00 6e 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 } //01 00  Layered Hidden Window
		$a_00_5 = {75 72 6c 64 6f 77 6e 6c 6f 61 64 74 6f 66 69 6c 65 61 } //01 00  urldownloadtofilea
		$a_01_6 = {56 69 64 65 6f 42 69 6f 73 44 61 74 65 } //01 00  VideoBiosDate
		$a_01_7 = {53 79 73 74 65 6d 42 69 6f 73 44 61 74 65 } //00 00  SystemBiosDate
	condition:
		any of ($a_*)
 
}