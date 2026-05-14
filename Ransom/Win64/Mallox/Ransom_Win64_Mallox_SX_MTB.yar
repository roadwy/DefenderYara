
rule Ransom_Win64_Mallox_SX_MTB{
	meta:
		description = "Ransom:Win64/Mallox.SX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 04 00 00 "
		
	strings :
		$a_01_0 = {0f 57 c0 0f 11 01 4c 89 79 10 4c 89 79 18 0f 10 04 11 48 8d 49 20 48 8d 04 11 0f 11 41 e0 0f 10 4c 11 f0 0f 11 49 f0 4c 89 7c 11 f0 48 c7 44 11 f8 07 00 00 00 66 44 89 7c 11 e0 48 3b c3 75 c0 } //20
		$a_01_1 = {c5 f9 ef c0 c5 f8 11 01 4c 89 79 10 4c 89 79 18 c5 fc 10 04 11 c5 fc 11 01 4c 89 7c 11 10 48 c7 44 11 18 07 00 00 00 66 44 89 3c 11 48 8d 49 20 48 8d 04 11 48 3b c3 75 c7 } //20
		$a_01_2 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //5 Your files has been encrypted
		$a_01_3 = {49 6e 63 6c 75 64 65 20 79 6f 75 72 20 6b 65 79 20 69 6e 20 79 6f 75 72 20 6c 65 74 74 65 72 } //5 Include your key in your letter
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*20+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5) >=30
 
}