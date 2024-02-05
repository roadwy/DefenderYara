
rule TrojanDropper_Win32_Farfli_J_bit{
	meta:
		description = "TrojanDropper:Win32/Farfli.J!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 86 65 e0 00 10 34 91 88 86 80 e7 00 10 46 81 fe d8 03 00 00 72 e9 } //01 00 
		$a_01_1 = {25 73 5c 25 73 65 78 2e 64 6c 6c } //01 00 
		$a_01_2 = {41 6e 74 69 56 69 72 75 73 50 72 6f 64 75 63 74 } //01 00 
		$a_01_3 = {44 51 59 39 37 58 47 42 35 69 5a 34 56 66 33 4b 73 45 74 36 31 48 4c 6f 54 4f 75 49 71 4a 50 70 32 41 6c 6e 63 52 43 67 53 78 55 57 79 65 62 68 4d 64 6d 7a 76 46 6a 4e 77 6b 61 3d } //00 00 
	condition:
		any of ($a_*)
 
}