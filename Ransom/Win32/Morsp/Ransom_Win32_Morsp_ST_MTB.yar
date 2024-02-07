
rule Ransom_Win32_Morsp_ST_MTB{
	meta:
		description = "Ransom:Win32/Morsp.ST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {46 69 6c 65 73 20 6f 6e 20 79 6f 75 72 20 63 6f 6d 70 75 74 65 72 73 20 61 72 65 20 65 6e 63 6f 64 65 64 20 62 79 20 61 20 68 61 72 64 20 61 6c 67 6f 72 69 74 68 6d } //01 00  Files on your computers are encoded by a hard algorithm
		$a_81_1 = {44 4f 20 4e 4f 54 20 44 45 4c 45 54 45 20 74 68 65 20 65 6e 63 72 79 70 74 65 64 20 61 6e 64 20 72 65 61 64 6d 65 20 66 69 6c 65 73 } //01 00  DO NOT DELETE the encrypted and readme files
		$a_81_2 = {54 6f 20 67 65 74 20 69 6e 66 6f 72 6d 61 74 69 6f 6e 20 68 6f 77 20 74 6f 20 64 65 63 72 79 70 74 20 79 6f 75 72 20 66 69 6c 65 73 2c 20 77 72 69 74 65 20 74 6f 20 75 73 20 61 74 20 74 68 65 20 61 64 64 72 65 73 73 20 62 65 6c 6f 77 3a } //01 00  To get information how to decrypt your files, write to us at the address below:
		$a_81_3 = {2a 2e 6d 6f 72 73 65 6f 70 2d } //01 00  *.morseop-
		$a_81_4 = {72 65 2d 64 65 63 72 79 70 74 20 66 69 6c 65 20 25 77 73 2c 20 25 77 73 } //01 00  re-decrypt file %ws, %ws
		$a_81_5 = {41 66 74 65 72 20 72 65 63 65 69 76 69 6e 67 20 62 69 74 63 6f 69 6e 73 20 57 65 20 77 69 6c 6c 20 73 65 6e 64 20 79 6f 75 20 61 6e 79 20 79 6f 75 20 6e 65 65 64 20 74 6f 20 72 65 73 74 6f 72 65 20 6e 6f 72 6d 61 6c 20 6f 70 65 72 61 74 69 6f 6e 20 6f 66 20 79 6f 75 72 20 6e 65 74 77 6f 72 6b } //00 00  After receiving bitcoins We will send you any you need to restore normal operation of your network
		$a_00_6 = {5d 04 00 } //00 e9 
	condition:
		any of ($a_*)
 
}