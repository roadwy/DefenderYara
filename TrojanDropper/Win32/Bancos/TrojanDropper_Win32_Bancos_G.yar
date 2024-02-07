
rule TrojanDropper_Win32_Bancos_G{
	meta:
		description = "TrojanDropper:Win32/Bancos.G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 57 69 6e 64 6f 77 73 20 4c 69 76 65 20 48 65 6c 70 5c 63 73 73 72 73 73 2e 65 78 65 } //01 00  \Windows Live Help\cssrss.exe
		$a_02_1 = {5c 57 69 6e 64 6f 77 73 20 4d 65 64 69 61 20 50 6c 61 79 65 72 5c 90 02 05 6c 76 6d 78 2e 65 78 65 90 00 } //01 00 
		$a_00_2 = {43 6f 70 79 72 69 67 68 74 20 28 63 29 20 31 39 39 39 2c 32 30 30 33 20 41 76 65 6e 67 65 72 20 62 79 20 4e 68 54 } //00 00  Copyright (c) 1999,2003 Avenger by NhT
	condition:
		any of ($a_*)
 
}