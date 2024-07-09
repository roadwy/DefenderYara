
rule Trojan_Win32_Ekstak_ASEA_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 85 cb 71 00 f7 2e 6e 00 00 c0 0a 00 0d 15 b6 76 a6 07 6e } //5
		$a_01_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 e2 e4 69 00 04 49 66 00 00 be 0a 00 d4 bd 14 99 a4 02 66 00 00 d4 } //5
		$a_01_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 91 51 69 00 b3 b5 65 00 00 be 0a 00 d4 bd 14 99 54 6f 65 00 00 d4 } //5
		$a_01_3 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 c0 0c 69 00 e2 70 65 00 00 be 0a 00 d4 bd 14 99 } //5
		$a_01_4 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 6a 7f 69 00 8c e3 65 00 00 be 0a 00 d4 bd 14 99 } //5
		$a_03_5 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 af [0-04] fb 65 00 00 be 0a 00 d4 bd 14 99 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_03_5  & 1)*5) >=5
 
}