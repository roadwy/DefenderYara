
rule Trojan_Win64_Lazy_A_MTB{
	meta:
		description = "Trojan:Win64/Lazy.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 81 f3 77 9e b4 57 48 01 d8 03 f7 48 81 ec 28 00 00 00 89 b5 94 fa ff ff 29 b5 54 f9 ff ff 33 fe 81 c7 13 c3 00 00 66 81 ef 35 eb 89 b5 b8 f9 ff ff 81 c6 38 9c 00 00 c7 85 1c fa ff ff 5f 07 00 00 81 ee 95 12 00 00 81 ef f4 24 00 00 81 f7 99 c8 00 00 e9 4e e6 ff ff } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}