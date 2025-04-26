
rule Backdoor_Linux_Mirai_QA_MTB{
	meta:
		description = "Backdoor:Linux/Mirai.QA!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {02 80 00 06 92 10 20 14 90 06 20 08 40 00 0a 79 92 10 00 11 92 10 20 14 c0 36 e0 0a } //1
		$a_00_1 = {c2 0b 00 0b 82 03 40 01 9a 03 7f ff 82 18 40 02 c2 28 c0 00 86 00 ff ff 88 01 20 01 82 02 60 02 80 a1 00 01 32 bf ff f7 } //1
		$a_00_2 = {12 80 00 0a 11 00 00 65 c2 0f bf d8 c2 2f bf da c2 0f bf d9 c0 2f bf dc c2 2f bf db 82 10 20 30 c2 2f bf d9 c2 2f bf d8 92 10 20 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}