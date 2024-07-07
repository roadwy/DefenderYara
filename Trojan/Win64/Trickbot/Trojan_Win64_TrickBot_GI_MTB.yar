
rule Trojan_Win64_TrickBot_GI_MTB{
	meta:
		description = "Trojan:Win64/TrickBot.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4d 63 c2 4d 8d 5b 01 48 8b c7 41 ff c2 49 f7 e0 48 c1 ea 02 48 6b ca 16 4c 2b c1 42 0f b6 44 84 20 41 30 43 ff 41 81 fa 00 16 03 00 72 } //1
		$a_81_1 = {53 72 65 69 73 6d 65 6f 57 } //1 SreismeoW
		$a_81_2 = {61 64 61 62 79 76 69 75 69 6b 65 65 66 72 72 75 } //1 adabyviuikeefrru
		$a_81_3 = {7a 6f 6f 67 64 76 6d 70 77 65 67 } //1 zoogdvmpweg
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}