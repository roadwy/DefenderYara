
rule Trojan_Win32_Ekstak_GAN_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.GAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 04 00 00 "
		
	strings :
		$a_01_0 = {6b 64 00 00 c0 0a 00 0d 15 b6 76 72 25 64 00 00 d4 00 00 57 93 06 be 00 00 01 00 04 00 10 10 } //10
		$a_01_1 = {2a 01 00 00 00 0d 31 7c 00 7f 94 78 00 00 c0 0a 00 0d 15 b6 76 f3 4d 78 00 00 d4 00 00 } //10
		$a_01_2 = {00 d0 88 60 00 6e 59 5a 00 00 fa 0e 00 a6 b9 6a 79 61 49 58 00 00 } //10
		$a_01_3 = {2a 01 00 00 00 9a d7 5f 00 38 a8 59 00 00 fa 0e 00 a6 b9 6a 79 ea 97 57 00 00 0e } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10) >=10
 
}
rule Trojan_Win32_Ekstak_GAN_MTB_2{
	meta:
		description = "Trojan:Win32/Ekstak.GAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_03_0 = {2a 01 00 00 00 67 53 80 00 89 b7 7c 00 00 be 0a 00 d4 bd 14 99 0c 7b 90 01 02 00 d4 00 00 1e 90 00 } //10
		$a_03_1 = {2a 01 00 00 00 2c 96 80 00 4e fa 7c 00 00 be 0a 00 d4 bd 14 99 ef bd 90 01 02 00 d4 00 00 90 00 } //10
		$a_01_2 = {2a 01 00 00 00 23 13 6b 00 45 77 67 00 00 be 0a 00 d4 bd 14 99 f4 30 67 00 00 d4 00 00 b4 21 } //10
		$a_01_3 = {2a 01 00 00 00 d3 d7 6b 00 f5 3b 68 00 00 be 0a 00 d4 bd 14 99 77 f5 67 00 00 d4 00 00 df } //10
		$a_01_4 = {2a 01 00 00 00 30 0c 6b 00 52 70 67 00 00 be 0a 00 d4 bd 14 99 d8 29 67 00 00 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10) >=10
 
}