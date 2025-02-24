
rule Trojan_Win64_CoinMiner_BR_MTB{
	meta:
		description = "Trojan:Win64/CoinMiner.BR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 58 6f e4 74 7c a4 ff 34 4a 95 ff 23 37 7c ff 21 34 73 ff 1e 32 6d ff 19 2b 5f ff 23 38 75 ff 24 3d 81 ff 42 5b 99 ff 40 58 } //2
		$a_01_1 = {3c 01 03 1a ab 17 1d 4a fc 3c 46 7b ff 31 48 91 ff 31 4a 96 ff 33 53 9a ff 34 47 83 ff 08 0c 34 dc } //2
		$a_01_2 = {75 52 30 33 45 74 00 00 66 66 64 73 } //1
		$a_01_3 = {34 64 61 62 32 61 39 37 2d 30 32 62 30 2d 34 34 35 31 2d 61 32 39 35 2d 61 65 38 64 66 37 30 38 34 64 36 32 } //1 4dab2a97-02b0-4451-a295-ae8df7084d62
		$a_01_4 = {43 6c 69 63 6b 20 61 6e 64 20 64 72 61 67 20 74 68 69 73 20 63 6f 6c 6f 72 20 6f 6e 74 6f 20 74 68 65 20 72 6f 62 6f 74 21 } //1 Click and drag this color onto the robot!
		$a_01_5 = {72 00 6f 00 62 00 6f 00 74 00 5f 00 64 00 65 00 6d 00 6f 00 } //1 robot_demo
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}