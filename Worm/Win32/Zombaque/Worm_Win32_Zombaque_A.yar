
rule Worm_Win32_Zombaque_A{
	meta:
		description = "Worm:Win32/Zombaque.A,SIGNATURE_TYPE_PEHSTR,08 00 08 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 61 73 74 69 6e 67 20 43 50 55 20 74 69 6d 65 } //01 00  Wasting CPU time
		$a_01_1 = {49 6e 74 65 6c 6c 69 67 65 6e 74 20 50 32 50 20 5a 6f 6d 62 69 65 } //01 00  Intelligent P2P Zombie
		$a_01_2 = {4d 61 64 65 20 69 6e 20 55 53 53 52 } //01 00  Made in USSR
		$a_01_3 = {71 77 65 72 74 79 75 69 6c 6b 6a 68 7a 78 63 76 } //01 00  qwertyuilkjhzxcv
		$a_01_4 = {74 6d 70 20 25 73 79 73 74 65 6d 72 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c 69 70 7a } //01 00  tmp %systemroot%\system32\ipz
		$a_01_5 = {25 64 20 25 30 32 64 3a 25 30 32 64 3a 25 30 32 64 5d 20 25 73 } //01 00  %d %02d:%02d:%02d] %s
		$a_01_6 = {23 25 64 20 28 50 41 53 53 29 20 72 65 63 65 69 76 65 64 20 63 6f 6e 6e 65 63 74 69 6f 6e 20 66 72 6f 6d 20 25 73 } //01 00  #%d (PASS) received connection from %s
		$a_01_7 = {31 71 32 77 33 65 34 72 35 74 } //01 00  1q2w3e4r5t
		$a_01_8 = {62 69 6c 6c 67 61 74 65 73 } //01 00  billgates
		$a_01_9 = {64 61 72 74 68 76 61 64 65 72 } //00 00  darthvader
	condition:
		any of ($a_*)
 
}