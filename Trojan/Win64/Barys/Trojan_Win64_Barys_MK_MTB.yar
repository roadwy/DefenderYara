
rule Trojan_Win64_Barys_MK_MTB{
	meta:
		description = "Trojan:Win64/Barys.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 02 00 00 "
		
	strings :
		$a_01_0 = {49 8d 42 01 44 0f b6 d0 42 0f b6 4c 15 40 49 8d 04 09 44 0f b6 c8 42 0f b6 44 0d 40 42 88 44 15 40 42 88 4c 0d 40 42 0f b6 44 15 40 48 03 c1 0f b6 c0 0f b6 4c 05 40 41 30 0c 10 48 ff c2 49 3b d6 } //20
		$a_01_1 = {5c 61 63 63 65 73 73 5f 74 6f 6b 65 6e 2e 74 78 74 } //15 \access_token.txt
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*15) >=35
 
}
rule Trojan_Win64_Barys_MK_MTB_2{
	meta:
		description = "Trojan:Win64/Barys.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 06 00 00 "
		
	strings :
		$a_01_0 = {49 89 cd 44 89 c5 0f 43 da 41 89 f0 48 89 ca 31 ff 48 8d 0d 3a ad 00 00 44 0f b7 f6 41 89 d9 } //25
		$a_01_1 = {53 74 61 72 74 69 6e 67 20 55 44 50 20 41 74 74 61 63 6b 20 2d 20 54 61 72 67 65 74 3a 20 25 73 2c 20 50 6f 72 74 3a 20 25 64 2c 20 54 68 72 65 61 64 73 3a 20 25 64 } //5 Starting UDP Attack - Target: %s, Port: %d, Threads: %d
		$a_01_2 = {53 74 61 72 74 69 6e 67 20 53 41 4d 50 20 41 74 74 61 63 6b 20 2d 20 54 61 72 67 65 74 3a 20 25 73 2c 20 50 6f 72 74 3a 20 25 64 2c 20 54 68 72 65 61 64 73 3a 20 25 64 } //5 Starting SAMP Attack - Target: %s, Port: %d, Threads: %d
		$a_01_3 = {53 74 61 72 74 69 6e 67 20 49 43 4d 50 20 66 6c 6f 6f 64 20 2d 20 54 61 72 67 65 74 3a 20 25 73 2c 20 54 68 72 65 61 64 73 3a 20 25 64 } //5 Starting ICMP flood - Target: %s, Threads: %d
		$a_01_4 = {53 74 61 72 74 69 6e 67 20 44 69 73 63 6f 72 64 20 41 74 74 61 63 6b 20 2d 20 54 61 72 67 65 74 3a 20 25 73 2c 20 50 6f 72 74 3a 20 25 64 2c 20 54 68 72 65 61 64 73 3a 20 25 64 } //5 Starting Discord Attack - Target: %s, Port: %d, Threads: %d
		$a_01_5 = {47 6c 6f 62 61 6c 5c 4d 79 42 6f 74 4d 75 74 65 78 } //5 Global\MyBotMutex
	condition:
		((#a_01_0  & 1)*25+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5) >=50
 
}