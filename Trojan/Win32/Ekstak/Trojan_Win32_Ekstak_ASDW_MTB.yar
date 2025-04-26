
rule Trojan_Win32_Ekstak_ASDW_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASDW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 e4 f8 69 00 06 5d 66 00 00 be 0a 00 d4 bd 14 99 bc 16 66 00 00 d4 00 00 49 bd be 36 00 00 01 } //5
		$a_01_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 f2 9f 69 00 14 04 66 00 00 be 0a 00 d4 bd 14 99 c0 bd 65 00 00 d4 00 00 91 fb b8 1a 00 } //5
		$a_01_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 d7 69 69 00 f9 cd 65 00 00 be 0a 00 d4 bd 14 99 9b 87 65 00 00 d4 00 00 ba fa 69 f9 } //5
		$a_01_3 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 28 e6 68 00 4a 4a 65 00 00 be 0a 00 d4 bd 14 99 e2 } //5
		$a_01_4 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 e5 fe 69 00 07 63 66 00 00 be 0a 00 d4 bd 14 99 a2 } //5
		$a_01_5 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 2f f4 69 00 51 58 66 00 00 be 0a 00 d4 bd 14 99 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5) >=5
 
}