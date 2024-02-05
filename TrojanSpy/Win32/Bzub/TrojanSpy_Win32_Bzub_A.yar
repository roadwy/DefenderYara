
rule TrojanSpy_Win32_Bzub_A{
	meta:
		description = "TrojanSpy:Win32/Bzub.A,SIGNATURE_TYPE_PEHSTR,2a 00 2a 00 08 00 00 0a 00 "
		
	strings :
		$a_01_0 = {31 32 33 61 62 25 2e 38 6c 78 } //0a 00 
		$a_01_1 = {49 65 48 6f 6f 6b 2e 64 6c 6c } //0a 00 
		$a_01_2 = {5c 68 6f 73 74 77 6c 2e 65 78 65 } //0a 00 
		$a_01_3 = {5c 66 6c 61 73 68 2e 7a 69 70 } //0a 00 
		$a_01_4 = {70 61 79 6d 65 6e 74 73 2e 61 73 70 } //01 00 
		$a_01_5 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d } //01 00 
		$a_01_6 = {5c 4d 61 63 72 6f 6d 65 64 69 61 5c 46 6c 61 73 68 20 50 6c 61 79 65 72 } //01 00 
		$a_01_7 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //00 00 
	condition:
		any of ($a_*)
 
}