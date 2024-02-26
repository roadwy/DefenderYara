
rule Trojan_Win32_Ekstak_ASDX_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASDX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 2c 96 80 00 4e fa 7c 00 00 be 0a 00 d4 bd 14 99 ef bd 7c 00 00 d4 } //05 00 
		$a_01_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 e7 df 71 00 59 43 6e 00 00 c0 0a 00 0d 15 b6 76 28 1c 6e 00 00 d4 00 00 c3 71 } //05 00 
		$a_01_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 fb cd 73 00 6d 31 70 00 00 c0 0a 00 0d 15 b6 76 1a 0a 70 00 00 d4 00 00 04 57 05 8a 00 00 01 } //05 00 
		$a_01_3 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 a6 6b 71 00 18 cf 6d 00 00 c0 0a 00 0d 15 b6 76 cf a7 6d 00 00 d4 00 00 ff 3c 5c bb 00 00 01 00 } //05 00 
		$a_01_4 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 67 53 80 00 89 b7 7c 00 00 be 0a 00 d4 bd 14 99 0c 7b 7c 00 00 d4 00 00 1e 3d 79 c6 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}