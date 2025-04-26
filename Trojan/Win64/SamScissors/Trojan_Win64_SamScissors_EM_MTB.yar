
rule Trojan_Win64_SamScissors_EM_MTB{
	meta:
		description = "Trojan:Win64/SamScissors.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 03 d6 c1 fa 03 8b ca c1 e9 1f 03 d1 6b ca 0f 44 2b f1 41 ff c6 44 89 6c 24 30 4c 89 6c 24 38 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win64_SamScissors_EM_MTB_2{
	meta:
		description = "Trojan:Win64/SamScissors.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {4d 89 c1 49 c1 e9 3f 49 c1 e8 21 45 01 c8 41 c1 e0 02 47 8d 04 40 44 29 c2 8a 14 0a 88 94 04 50 04 00 00 } //2
		$a_01_1 = {8a 94 04 50 03 00 00 00 d1 02 8c 04 50 04 00 00 44 0f b6 c1 46 8a 8c 04 50 03 00 00 42 88 94 04 50 03 } //3
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3) >=5
 
}