
rule Trojan_Win64_Tedy_ARAZ_MTB{
	meta:
		description = "Trojan:Win64/Tedy.ARAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 4c 24 58 4c 89 e2 8d 44 00 02 48 89 5c 24 20 41 b9 01 00 00 00 89 44 24 28 ff 15 ec ef 0e 00 } //2
		$a_01_1 = {48 83 c1 01 0f b6 04 10 41 30 01 48 39 cb 75 df } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}