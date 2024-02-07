
rule TrojanProxy_Win32_Hostile_A{
	meta:
		description = "TrojanProxy:Win32/Hostile.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 69 6c 65 20 74 72 61 6e 73 20 66 61 69 6c 2e 00 00 00 00 31 30 38 20 25 64 2e 00 46 69 6c 65 20 74 72 61 6e 73 20 73 75 63 63 65 73 73 2e 00 4e 4f 20 46 49 4c 45 20 00 00 00 00 31 30 36 20 25 64 2e 00 31 30 35 20 25 64 2e 00 } //01 00 
		$a_01_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_01_2 = {47 45 54 20 68 74 74 70 3a 2f 2f } //00 00  GET http://
	condition:
		any of ($a_*)
 
}