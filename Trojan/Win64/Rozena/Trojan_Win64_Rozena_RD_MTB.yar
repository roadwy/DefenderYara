
rule Trojan_Win64_Rozena_RD_MTB{
	meta:
		description = "Trojan:Win64/Rozena.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 4a 40 8b 48 48 89 4a 48 0f b7 48 4c 66 89 4a 4c 33 c9 ba ce 01 00 00 44 8d 49 40 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Rozena_RD_MTB_2{
	meta:
		description = "Trojan:Win64/Rozena.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 ff c2 48 83 fa 0b 72 f0 90 09 07 00 8d 42 90 01 01 30 44 15 90 00 } //1
		$a_01_1 = {c7 85 b8 00 00 00 43 5d 5e 48 c7 85 bc 00 00 00 52 48 44 10 c7 85 c0 00 00 00 11 6e 00 01 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}