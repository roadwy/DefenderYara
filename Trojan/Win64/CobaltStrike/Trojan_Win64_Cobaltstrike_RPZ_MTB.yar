
rule Trojan_Win64_Cobaltstrike_RPZ_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 f7 e8 41 03 d0 c1 fa 09 8b ca c1 e9 1f 03 d1 69 ca ac 03 00 00 44 2b c1 41 fe c0 44 32 44 2b ff 45 32 c7 44 88 43 ff 48 83 ef 01 75 c0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_Cobaltstrike_RPZ_MTB_2{
	meta:
		description = "Trojan:Win64/Cobaltstrike.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b c8 c7 44 24 28 40 00 00 00 c7 44 24 20 00 30 00 00 4c 8d 4d c8 45 33 c0 48 8d 55 b0 ff d3 ff d7 48 8b 5d b0 4c 8d 4d b8 ba 0f 27 00 00 41 b8 40 00 00 00 48 8b cb ff 15 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}