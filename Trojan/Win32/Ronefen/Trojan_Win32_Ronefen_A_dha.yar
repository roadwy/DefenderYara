
rule Trojan_Win32_Ronefen_A_dha{
	meta:
		description = "Trojan:Win32/Ronefen.A!dha,SIGNATURE_TYPE_PEHSTR,03 00 02 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 5c 00 77 00 69 00 6e 00 66 00 65 00 6e 00 73 00 65 00 00 00 00 00 00 00 6d 00 73 00 68 00 74 00 61 00 20 00 76 00 62 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 45 00 78 00 65 00 63 00 75 00 } //01 00 
		$a_01_1 = {65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 00 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 00 00 00 00 45 00 6c 00 65 00 76 00 61 00 74 00 69 00 6f 00 6e 00 3a 00 41 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 6f 00 72 00 21 00 6e 00 65 00 77 00 3a 00 00 00 } //01 00 
		$a_01_2 = {33 32 20 62 69 74 20 70 61 79 6c 6f 61 64 73 20 63 61 6e 20 62 65 20 69 6e 6a 65 63 74 65 64 20 66 72 6f 6d 20 33 32 62 69 74 20 6c 6f 61 64 } //01 00 
		$a_01_3 = {46 00 30 00 45 00 34 00 39 00 38 00 33 00 34 00 38 00 43 00 37 00 37 00 33 00 38 00 41 00 41 00 30 00 32 00 33 00 45 00 39 00 36 00 43 00 38 00 39 00 33 00 33 00 37 00 35 00 33 00 35 00 45 00 42 00 43 00 32 00 34 00 38 00 44 00 39 00 34 00 30 00 43 00 45 00 30 00 37 00 34 00 45 00 33 00 31 00 37 00 32 00 37 00 33 00 32 00 33 00 30 00 } //01 00 
		$a_01_4 = {77 00 69 00 6e 00 6d 00 67 00 6d 00 74 00 00 00 65 72 72 6f 72 00 00 00 52 00 65 00 61 00 6c 00 74 00 65 00 6b 00 20 00 48 00 44 00 20 00 41 00 75 00 64 00 69 00 6f 00 00 } //00 00 
		$a_01_5 = {00 87 } //10 00 
	condition:
		any of ($a_*)
 
}