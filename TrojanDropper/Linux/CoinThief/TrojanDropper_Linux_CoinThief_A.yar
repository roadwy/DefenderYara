
rule TrojanDropper_Linux_CoinThief_A{
	meta:
		description = "TrojanDropper:Linux/CoinThief.A,SIGNATURE_TYPE_MACHOHSTR_EXT,0c 00 0c 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {43 6f 6e 74 65 6e 74 73 2f 5f 43 6f 64 65 53 69 67 6e 61 74 75 72 65 00 2e 64 53 59 4d 00 2e 73 69 67 } //02 00  潃瑮湥獴弯潃敤楓湧瑡牵e搮奓M献杩
		$a_01_1 = {2f 75 73 72 2f 62 69 6e 2f 74 61 72 00 2d 78 43 00 2d 66 } //02 00 
		$a_01_2 = {66 73 36 33 34 38 39 32 33 6c 6f 63 6b 00 41 67 65 6e 74 } //02 00 
		$a_01_3 = {4c 32 4a 70 62 69 39 73 59 58 56 75 59 32 68 6a 64 47 77 3d } //02 00  L2Jpbi9sYXVuY2hjdGw=
		$a_01_4 = {52 58 68 30 5a 57 35 7a 61 57 39 75 4c 6d 4e 6f 63 6d 39 74 5a 51 3d 3d } //02 00  RXh0ZW5zaW9uLmNocm9tZQ==
		$a_01_5 = {55 32 46 6d 59 58 4a 70 4c 30 56 34 64 47 56 75 63 32 6c 76 62 6e 4d 3d } //00 00  U2FmYXJpL0V4dGVuc2lvbnM=
		$a_00_6 = {5d 04 00 00 4d 14 } //03 80 
	condition:
		any of ($a_*)
 
}