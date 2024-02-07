
rule Trojan_Win32_Hostblock_V{
	meta:
		description = "Trojan:Win32/Hostblock.V,SIGNATURE_TYPE_PEHSTR_EXT,20 00 20 00 06 00 00 0a 00 "
		
	strings :
		$a_00_0 = {31 32 37 2e 30 2e 30 2e 31 09 00 } //0a 00 
		$a_00_1 = {5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //0a 00  \drivers\etc\hosts
		$a_02_2 = {0f b6 56 28 8b 46 24 8a 92 90 01 04 30 14 08 90 01 02 28 03 c1 80 7e 28 2e 76 04 c6 46 28 00 90 02 02 3b 4e 10 72 90 00 } //01 00 
		$a_00_3 = {50 00 6c 00 65 00 61 00 73 00 65 00 2c 00 20 00 72 00 75 00 6e 00 20 00 74 00 68 00 69 00 73 00 20 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 20 00 61 00 73 00 20 00 41 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 6f 00 72 00 21 00 } //01 00  Please, run this program as Administrator!
		$a_00_4 = {6f 76 4c 7a 63 33 4c 6a 49 79 4d 53 34 78 4e 54 4d 75 4d 54 63 77 4c 33 52 6c 63 33 51 75 63 47 68 77 50 32 74 6c 65 54 30 71 77 65 72 74 } //01 00  ovLzc3LjIyMS4xNTMuMTcwL3Rlc3QucGhwP2tleT0qwert
		$a_00_5 = {73 64 66 6b 6a 76 6e 73 6c 64 6b 66 6a 76 6e } //00 00  sdfkjvnsldkfjvn
	condition:
		any of ($a_*)
 
}