
rule Trojan_Win32_Ekstak_ASDY_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASDY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 7d 13 81 00 9f 77 7d 00 00 be 90 02 04 14 99 2c 3b 7d 90 00 } //5
		$a_01_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 45 e6 7f 00 67 4a 7c 00 00 be 0a 00 d4 bd 14 99 ed 0d 7c 00 00 d4 00 00 b3 8c d2 42 } //5
		$a_03_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 56 4e 6b 00 78 b2 67 00 00 be 90 02 04 14 99 02 6c 67 90 00 } //5
		$a_03_3 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 17 a4 6b 00 39 08 68 00 00 be 90 02 04 14 99 db c1 90 00 } //5
		$a_01_4 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 c9 e0 6b 00 eb 44 68 00 00 be 0a 00 d4 bd 14 99 6b fe 67 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5+(#a_03_2  & 1)*5+(#a_03_3  & 1)*5+(#a_01_4  & 1)*5) >=5
 
}