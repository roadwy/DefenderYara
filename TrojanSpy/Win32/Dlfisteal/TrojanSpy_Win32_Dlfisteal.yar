
rule TrojanSpy_Win32_Dlfisteal{
	meta:
		description = "TrojanSpy:Win32/Dlfisteal,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {34 66 6f 6c 6b 6f 70 74 69 6f 6e 73 2e 69 6e 66 6f } //01 00  4folkoptions.info
		$a_01_1 = {3a 5c 55 73 65 72 73 5c 46 6c 79 33 31 31 30 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 69 6e 73 74 61 6c 6c 65 72 32 5f 32 30 31 37 5c 52 65 6c 65 61 73 65 5c 66 69 6e 64 65 72 2e 70 64 62 00 } //01 00 
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 46 69 6e 64 65 72 00 } //00 00 
		$a_00_3 = {5d } //04 00  ]
	condition:
		any of ($a_*)
 
}