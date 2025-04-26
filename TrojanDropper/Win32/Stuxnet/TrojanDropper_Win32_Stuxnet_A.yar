
rule TrojanDropper_Win32_Stuxnet_A{
	meta:
		description = "TrojanDropper:Win32/Stuxnet.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 04 00 06 00 00 "
		
	strings :
		$a_03_0 = {56 8b 70 3c 03 f0 81 3e 50 45 00 00 74 04 33 c0 5e [0-08] 0f b7 46 14 53 57 8d 7c 30 18 33 c0 33 db 66 3b 46 06 73 } //3
		$a_01_1 = {74 12 0f b7 46 06 43 83 c7 28 3b d8 7c e4 33 c0 } //1
		$a_01_2 = {8d 57 01 d1 ea 8d 34 0a 8a 14 06 30 14 08 40 3b 45 fc 72 f4 } //3
		$a_03_3 = {81 38 0d 12 39 ae 75 ?? 8b 54 24 10 83 c0 04 89 02 8b 44 24 14 } //3
		$a_01_4 = {83 c4 0c 8d 45 80 35 dd 79 19 ae 33 c9 89 45 80 } //3
		$a_01_5 = {83 bd fc fe ff ff 02 75 17 83 bd f0 fe ff ff 05 73 09 83 bd f0 fe ff ff 06 } //1
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*3+(#a_03_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*1) >=4
 
}