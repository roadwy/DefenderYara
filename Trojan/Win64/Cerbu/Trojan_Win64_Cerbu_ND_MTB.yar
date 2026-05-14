
rule Trojan_Win64_Cerbu_ND_MTB{
	meta:
		description = "Trojan:Win64/Cerbu.ND!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {45 0f 57 ff 4c 8b 35 b0 3c 78 00 65 4d 8b 36 4d 8b 36 31 c0 48 c7 00 00 00 00 00 48 83 c4 } //2
		$a_01_1 = {48 89 11 49 89 d6 48 8b 62 38 48 89 fa 48 8b 3f ff d7 48 8b 0d d0 9e 74 00 65 48 8b 09 48 8b 01 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}