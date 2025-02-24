
rule Trojan_Win64_Tedy_NM_MTB{
	meta:
		description = "Trojan:Win64/Tedy.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {e8 f1 03 00 00 48 c7 44 24 30 00 00 00 00 c7 44 24 28 00 00 00 00 c7 44 24 20 02 00 00 00 48 89 d9 ba 00 00 00 40 41 b8 02 00 00 00 45 31 c9 } //2
		$a_01_1 = {48 81 ff 00 80 00 00 41 bc 00 80 00 00 4c 0f 42 e7 4c 89 f1 4c 89 e2 e8 d4 0c 00 00 c7 44 24 70 00 00 00 00 48 c7 44 24 20 00 00 00 00 4c 89 f9 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}