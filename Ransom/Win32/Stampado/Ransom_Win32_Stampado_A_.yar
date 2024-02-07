
rule Ransom_Win32_Stampado_A_{
	meta:
		description = "Ransom:Win32/Stampado.A!!Stampado.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_03_0 = {43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 90 02 04 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 55 00 70 00 64 00 61 00 74 00 65 00 90 00 } //01 00 
		$a_03_1 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 90 02 04 57 69 6e 64 6f 77 73 20 55 70 64 61 74 65 90 00 } //01 00 
		$a_81_2 = {2e 6c 6f 63 6b 65 64 } //01 00  .locked
		$a_81_3 = {70 68 69 6c 61 64 65 6c 70 68 69 61 5f 64 65 62 75 67 2e 74 78 74 } //01 00  philadelphia_debug.txt
		$a_81_4 = {44 6f 6e 65 20 69 6e 66 65 63 74 69 6e 67 20 6e 65 74 77 6f 72 6b } //01 00  Done infecting network
		$a_81_5 = {45 6e 63 72 79 70 74 65 64 20 66 69 6c 65 6e 61 6d 65 } //02 00  Encrypted filename
		$a_81_6 = {73 68 65 6c 6c 65 78 65 63 75 74 65 3d 6d 79 44 69 73 6b 5c 64 72 69 76 65 72 73 2e 65 78 65 } //05 00  shellexecute=myDisk\drivers.exe
	condition:
		any of ($a_*)
 
}