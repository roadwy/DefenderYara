
rule Trojan_Win32_Convagent_CH_MTB{
	meta:
		description = "Trojan:Win32/Convagent.CH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {da b6 e9 46 76 e9 5e 76 db ae f3 eb 16 64 65 65 b6 65 b9 8e e9 5e 66 db 9f ce 66 67 66 66 f3 eb 16 63 65 65 b6 65 b9 7e f3 eb 16 63 65 65 b6 d0 66 d0 66 b6 65 b9 92 f3 eb 16 63 65 65 b6 65 b9 9a f3 eb 16 63 } //01 00 
		$a_01_1 = {e7 a1 b3 c0 db 5b f1 59 69 d9 a2 e7 a4 b6 ab 66 66 db 4e f1 29 c1 29 bb f1 52 e9 2a 4e b9 f1 c3 76 bc 99 26 9f ab 72 bd f1 e3 7a ef 6d 2d ab 56 66 62 65 65 ef c3 52 75 ec a4 67 66 66 51 69 } //01 00 
		$a_01_2 = {8d 8c 24 8c 00 00 00 c6 84 24 98 00 00 00 1d e8 9d 02 00 00 8b 44 24 20 50 ff d3 83 c4 04 3b f5 8b c8 75 28 3b cd 75 24 8b 1d 78 31 40 00 6a 10 ff d3 99 2b c2 6a 11 8b f0 d1 fe ff d3 6a 04 8b e8 ff d3 03 c5 99 2b c2 } //01 00 
		$a_01_3 = {a6 a1 37 75 ea 41 66 66 66 f1 bb 56 a1 37 e2 6d 69 39 ef bb 62 51 74 e7 60 66 62 65 65 ef c3 62 e3 69 ef b3 62 99 38 ef b3 5e f1 5e 27 55 69 f1 a2 a4 f1 2e e9 47 6d 39 55 f1 30 e9 4d 67 39 4d 6f e3 5e a8 a6 e9 60 70 } //01 00 
		$a_01_4 = {55 49 5c 63 61 6e 76 61 73 2e 62 6d 70 } //01 00 
		$a_01_5 = {58 4d 65 64 69 61 55 49 46 61 63 74 6f 72 79 2e 64 6c 6c } //01 00 
		$a_01_6 = {75 00 63 00 61 00 73 00 74 00 2e 00 63 00 6f 00 6d 00 2e 00 63 00 6e 00 } //00 00 
	condition:
		any of ($a_*)
 
}