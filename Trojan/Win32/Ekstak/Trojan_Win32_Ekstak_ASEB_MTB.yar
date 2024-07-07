
rule Trojan_Win32_Ekstak_ASEB_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 6b c6 61 00 dd 29 5e 00 00 c0 0a 00 0d 15 b6 76 68 } //5
		$a_01_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 3e bf 61 00 b0 22 5e 00 00 c0 0a 00 0d 15 b6 76 31 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=5
 
}
rule Trojan_Win32_Ekstak_ASEB_MTB_2{
	meta:
		description = "Trojan:Win32/Ekstak.ASEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 84 db 7b 00 f6 3e 78 00 00 c0 0a 00 0d 15 b6 76 a3 f8 } //5
		$a_01_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 61 c8 7b 00 d3 2b 78 00 00 c0 0a 00 0d 15 b6 76 6f e5 77 } //5
		$a_01_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 13 57 7c 00 85 ba 78 00 00 c0 0a 00 0d 15 b6 76 18 74 } //5
		$a_01_3 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 71 fe 67 00 e3 61 64 00 00 c0 0a 00 0d 15 b6 76 4f 1b 64 } //5
		$a_01_4 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 18 d9 7b 00 8a 3c 78 00 00 c0 0a 00 0d 15 b6 76 1b f6 77 00 00 d4 00 00 4c 46 7f } //5
		$a_01_5 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 db f5 67 00 4d 59 64 00 00 c0 0a 00 0d 15 b6 76 b5 12 64 00 00 } //5
		$a_01_6 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 a6 05 68 00 18 69 64 00 00 c0 0a 00 0d 15 b6 76 7a 22 64 00 00 d4 00 00 6e e1 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5+(#a_01_6  & 1)*5) >=5
 
}