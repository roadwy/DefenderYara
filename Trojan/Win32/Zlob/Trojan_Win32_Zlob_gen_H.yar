
rule Trojan_Win32_Zlob_gen_H{
	meta:
		description = "Trojan:Win32/Zlob.gen!H,SIGNATURE_TYPE_PEHSTR_EXT,30 00 30 00 0c 00 00 01 00 "
		
	strings :
		$a_01_0 = {84 b2 96 b1 b4 ba 1a 10 b6 9c 00 aa 00 34 1d 07 } //01 00 
		$a_01_1 = {4f f2 50 30 b5 98 cf 11 bb 82 00 aa 00 bd ce 0b } //01 00 
		$a_01_2 = {25 44 2c 33 cb 26 d0 11 b4 83 00 c0 4f d9 01 19 } //01 00 
		$a_01_3 = {40 f2 50 30 b5 98 cf 11 bb 82 00 aa 00 bd ce 0b } //01 00 
		$a_01_4 = {1f f2 50 30 b5 98 cf 11 bb 82 00 aa 00 bd ce 0b } //01 00 
		$a_01_5 = {ff f1 50 30 b5 98 cf 11 bb 82 00 aa 00 bd ce 0b } //01 00 
		$a_01_6 = {a0 15 a7 34 87 65 d0 11 92 4a 00 20 af c7 ac 4d } //01 00 
		$a_01_7 = {61 16 0c d3 af cd d0 11 8a 3e 00 c0 4f c9 e2 6e } //0a 00 
		$a_02_8 = {44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 90 02 04 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 90 02 04 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 90 02 04 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 90 00 } //0a 00 
		$a_00_9 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //0a 00  IsDebuggerPresent
		$a_01_10 = {45 6e 63 6f 64 65 50 6f 69 6e 74 65 72 00 00 00 4b 45 52 4e 45 4c 33 32 2e 44 4c 4c 00 00 00 00 44 65 63 6f 64 65 50 6f 69 6e 74 65 72 00 00 00 46 6c 73 46 72 65 65 00 46 6c 73 53 65 74 56 61 6c 75 65 00 46 6c 73 47 65 74 56 61 6c 75 65 00 46 6c 73 41 6c 6c 6f 63 00 00 } //0a 00 
		$a_01_11 = {42 68 6f 4e 65 77 2e 44 4c 4c } //00 00  BhoNew.DLL
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Zlob_gen_H_2{
	meta:
		description = "Trojan:Win32/Zlob.gen!H,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {4f f2 50 30 b5 98 cf 11 bb 82 00 aa 00 bd ce 0b 25 44 2c 33 cb 26 d0 11 b4 83 00 c0 4f d9 01 19 40 f2 50 30 b5 98 cf 11 bb 82 00 aa 00 bd ce 0b 1f f2 50 30 b5 98 cf 11 bb 82 00 aa 00 bd ce 0b ff f1 50 30 b5 98 cf 11 bb 82 00 aa 00 bd ce 0b a0 15 a7 34 87 65 d0 11 92 4a 00 20 af c7 ac 4d 61 16 0c d3 af cd d0 11 8a 3e 00 c0 4f c9 e2 6e 84 b2 96 b1 b4 ba 1a 10 b6 9c 00 aa 00 34 1d 07 } //01 00 
		$a_03_1 = {a0 15 a7 34 87 65 d0 11 92 4a 00 20 af c7 ac 4d 61 16 0c d3 af cd d0 11 8a 3e 00 c0 4f c9 e2 6e 4f f2 50 30 b5 98 cf 11 bb 82 00 aa 00 bd ce 0b 25 44 2c 33 cb 26 d0 11 b4 83 00 c0 4f d9 01 19 90 03 10 00 03 f2 50 30 b5 98 cf 11 bb 82 00 aa 00 bd ce 0b 40 f2 50 30 b5 98 cf 11 bb 82 00 aa 00 bd ce 0b 1f f2 50 30 b5 98 cf 11 bb 82 00 aa 00 bd ce 0b ff f1 50 30 b5 98 cf 11 bb 82 00 aa 00 bd ce 0b 84 b2 96 b1 b4 ba 1a 10 b6 9c 00 aa 00 34 1d 07 90 00 } //01 00 
		$a_01_2 = {a0 15 a7 34 87 65 d0 11 92 4a 00 20 af c7 ac 4d 61 16 0c d3 af cd d0 11 8a 3e 00 c0 4f c9 e2 6e 84 b2 96 b1 b4 ba 1a 10 b6 9c 00 aa 00 34 1d 07 4f f2 50 30 b5 98 cf 11 bb 82 00 aa 00 bd ce 0b 25 44 2c 33 cb 26 d0 11 b4 83 00 c0 4f d9 01 19 40 f2 50 30 b5 98 cf 11 bb 82 00 aa 00 bd ce 0b 1f f2 50 30 b5 98 cf 11 bb 82 00 aa 00 bd ce 0b ff f1 50 30 b5 98 cf 11 bb 82 00 aa 00 bd ce 0b } //0a 00 
		$a_02_3 = {44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 90 02 04 44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 90 02 04 44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 90 02 04 44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 90 00 } //0a 00 
		$a_00_4 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //0a 00  IsDebuggerPresent
		$a_01_5 = {45 6e 63 6f 64 65 50 6f 69 6e 74 65 72 00 00 00 4b 45 52 4e 45 4c 33 32 2e 44 4c 4c 00 00 00 00 44 65 63 6f 64 65 50 6f 69 6e 74 65 72 00 00 00 46 6c 73 46 72 65 65 00 46 6c 73 53 65 74 56 61 6c 75 65 00 46 6c 73 47 65 74 56 61 6c 75 65 00 46 6c 73 41 6c 6c 6f 63 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}