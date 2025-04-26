
rule Trojan_Win64_Emotet_ED_MTB{
	meta:
		description = "Trojan:Win64/Emotet.ED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 8a 04 02 44 32 44 1c 50 44 88 04 33 48 ff c3 49 3b de 7c b4 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win64_Emotet_ED_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.ED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b ca d1 e9 03 ca c1 e9 04 89 4c 24 68 8b 4c 24 68 f7 e1 c1 ea 06 89 54 24 68 49 8b d2 81 } //6
	condition:
		((#a_01_0  & 1)*6) >=6
 
}
rule Trojan_Win64_Emotet_ED_MTB_3{
	meta:
		description = "Trojan:Win64/Emotet.ED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 6c 24 48 08 81 44 24 48 e7 d4 00 00 6b 44 24 48 0f 89 44 24 48 81 74 24 48 ff 94 0d 00 44 8b 44 24 48 8b 54 24 58 } //6
	condition:
		((#a_01_0  & 1)*6) >=6
 
}
rule Trojan_Win64_Emotet_ED_MTB_4{
	meta:
		description = "Trojan:Win64/Emotet.ED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 8b 4c 24 08 41 d3 e1 44 89 4c 24 3c 41 89 c1 44 89 ca 4c 8b 44 24 28 41 8a 0c 10 44 28 d9 4c 8b 54 24 18 41 88 0c 12 83 c0 20 44 8b 4c 24 24 44 39 c8 89 44 24 0c } //6
	condition:
		((#a_01_0  & 1)*6) >=6
 
}