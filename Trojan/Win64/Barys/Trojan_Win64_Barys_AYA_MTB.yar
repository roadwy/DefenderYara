
rule Trojan_Win64_Barys_AYA_MTB{
	meta:
		description = "Trojan:Win64/Barys.AYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 74 61 72 74 69 6e 67 20 55 44 50 20 50 61 79 6c 6f 61 64 20 41 74 74 61 63 6b } //2 Starting UDP Payload Attack
		$a_01_1 = {54 43 50 2d 52 41 4e 44 20 61 74 74 61 63 6b 20 6f 6e 20 25 73 3a 25 64 20 63 6f 6d 70 6c 65 74 65 64 } //2 TCP-RAND attack on %s:%d completed
		$a_01_2 = {41 74 74 65 6d 70 74 69 6e 67 20 74 6f 20 6b 69 6c 6c 20 54 43 50 20 63 6f 6e 6e 65 63 74 69 6f 6e 73 20 74 6f 20 74 61 72 67 65 74 20 70 6f 72 74 73 3a } //1 Attempting to kill TCP connections to target ports:
		$a_01_3 = {53 74 61 72 74 69 6e 67 20 44 69 73 63 6f 72 64 20 41 74 74 61 63 6b 20 2d 20 54 61 72 67 65 74 3a 20 25 73 2c 20 50 6f 72 74 3a 20 25 64 2c 20 54 68 72 65 61 64 73 3a 20 25 64 } //1 Starting Discord Attack - Target: %s, Port: %d, Threads: %d
		$a_01_4 = {53 74 61 72 74 69 6e 67 20 49 43 4d 50 20 66 6c 6f 6f 64 20 2d 20 54 61 72 67 65 74 3a 20 25 73 2c 20 54 68 72 65 61 64 73 3a 20 25 64 } //1 Starting ICMP flood - Target: %s, Threads: %d
		$a_01_5 = {53 74 61 72 74 69 6e 67 20 53 41 4d 50 20 41 74 74 61 63 6b 20 2d 20 54 61 72 67 65 74 3a } //1 Starting SAMP Attack - Target:
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}