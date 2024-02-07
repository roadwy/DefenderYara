
rule TrojanProxy_Win32_Jaber_A{
	meta:
		description = "TrojanProxy:Win32/Jaber.A,SIGNATURE_TYPE_PEHSTR_EXT,23 00 21 00 0f 00 00 0a 00 "
		
	strings :
		$a_01_0 = {4c 00 41 00 59 00 45 00 52 00 45 00 44 00 20 00 } //0a 00  LAYERED 
		$a_01_1 = {4d 00 7a 00 4e 00 61 00 6d 00 65 00 } //0a 00  MzName
		$a_01_2 = {53 4f 46 54 57 41 52 45 5c 57 69 6e 53 6f 63 6b 32 5c } //01 00  SOFTWARE\WinSock2\
		$a_00_3 = {6c 69 76 69 6e 67 20 65 76 65 72 20 73 69 6e 63 65 20 6f 6e 20 74 68 65 20 } //01 00  living ever since on the 
		$a_00_4 = {77 6f 6e 20 66 72 6f 6d 20 74 68 61 74 20 68 69 73 74 6f 72 79 2d 63 68 61 6e 67 69 6e 67 20 } //01 00  won from that history-changing 
		$a_00_5 = {74 68 65 20 65 78 70 6c 6f 73 69 6f 6e 20 6f 66 20 74 68 65 20 66 69 72 73 74 20 61 74 6f 6d 69 63 20 } //01 00  the explosion of the first atomic 
		$a_00_6 = {42 75 74 20 73 6d 75 67 6e 65 73 73 20 63 61 6e 20 62 72 65 65 64 20 } //01 00  But smugness can breed 
		$a_00_7 = {63 61 72 65 6c 65 73 73 6e 65 73 73 2e 20 49 6e 20 72 65 63 65 6e 74 20 79 65 61 72 73 20 } //01 00  carelessness. In recent years 
		$a_00_8 = {66 6f 72 20 69 74 73 20 73 75 63 63 65 73 73 65 73 20 62 75 74 20 69 74 73 20 66 61 69 6c 75 72 65 73 2e 20 } //01 00  for its successes but its failures. 
		$a_00_9 = {73 65 63 72 65 74 20 64 61 74 61 20 67 6f 69 6e 67 20 6d 69 73 73 69 6e 67 20 28 6f 6e 6c 79 20 } //01 00  secret data going missing (only 
		$a_00_10 = {24 36 30 20 6d 69 6c 6c 69 6f 6e 20 74 6f 20 24 37 30 20 6d 69 6c 6c 69 6f 6e 20 } //01 00  $60 million to $70 million 
		$a_00_11 = {73 65 6c 6c 20 70 69 74 73 20 66 6f 72 20 24 31 20 62 69 6c 6c 69 6f 6e 20 65 61 63 68 2c 20 77 65 20 } //01 00  sell pits for $1 billion each, we 
		$a_00_12 = {6e 65 76 65 72 20 6d 61 6b 65 20 61 20 70 72 6f 66 69 74 20 6e 6f 72 20 73 68 6f 75 6c 64 20 } //01 00  never make a profit nor should 
		$a_00_13 = {4d 6f 72 65 20 69 6d 70 6f 72 74 61 6e 74 6c 79 2c 20 74 68 65 20 32 30 20 73 6f 6d 65 20 } //01 00  More importantly, the 20 some 
		$a_00_14 = {74 68 65 20 65 6e 64 20 6f 66 20 74 68 65 20 65 6d 70 69 72 65 } //00 00  the end of the empire
	condition:
		any of ($a_*)
 
}