
rule TrojanSpy_Win32_Golopy_A{
	meta:
		description = "TrojanSpy:Win32/Golopy.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 3a 2f 2f 90 02 10 2e 6e 6f 2d 69 70 2e 6f 72 67 3a 31 30 38 30 2f 6c 6f 67 73 2f 67 65 74 6c 6f 67 2e 70 68 70 00 52 65 61 6c 74 65 6b 20 41 75 64 69 6f 00 5c 52 65 61 6c 74 65 6b 2e 65 78 65 00 5c 4c 6f 67 73 2e 74 78 74 90 00 } //01 00 
		$a_03_1 = {5b 25 73 5d 20 2d 20 25 64 3a 25 64 3a 25 64 20 25 64 2f 25 64 2f 25 64 90 02 10 3c 42 53 3e 00 3c 54 61 62 3e 00 3c 45 6e 74 65 72 3e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}