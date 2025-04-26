
rule Trojan_Win32_Ekstak_ER_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {2a 01 00 00 00 69 c5 6e 00 8b 29 6b 00 00 be 0a 00 d4 bd 14 99 0f e3 6a 00 00 d4 00 00 ef 12 a1 1a } //5
		$a_01_1 = {2a 01 00 00 00 61 29 6f 00 83 8d 6b 00 00 be 0a 00 d4 bd 14 99 ff 46 6b 00 00 d4 00 00 de c1 58 3a } //5
		$a_01_2 = {2a 01 00 00 00 85 1e 71 00 a7 82 6d 00 00 be 0a 00 d4 bd 14 99 2c 46 6d 00 00 d4 00 00 64 89 bf 96 } //5
		$a_01_3 = {2a 01 00 00 00 45 b8 6e 00 67 1c 6b 00 00 be 0a 00 d4 bd 14 99 f0 d5 6a 00 00 d4 00 00 01 0e c0 b3 } //5
		$a_01_4 = {2a 01 00 00 00 4e 30 6f 00 70 94 6b 00 00 be 0a 00 d4 bd 14 99 ee 4d 6b 00 00 d4 00 00 95 8e ae c9 } //5
		$a_01_5 = {52 00 42 00 75 00 74 00 74 00 6f 00 6e 00 54 00 52 00 41 00 59 00 } //1 RButtonTRAY
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*1) >=6
 
}