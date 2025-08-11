
rule Trojan_Win64_Tedy_PGT_MTB{
	meta:
		description = "Trojan:Win64/Tedy.PGT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {4d 00 79 00 53 00 74 00 61 00 72 00 74 00 75 00 70 00 41 00 70 00 70 } //1
		$a_01_1 = {30 01 48 8d 49 01 48 83 eb 01 75 f4 } //4
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*4) >=5
 
}
rule Trojan_Win64_Tedy_PGT_MTB_2{
	meta:
		description = "Trojan:Win64/Tedy.PGT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 33 c4 48 89 84 24 a0 03 00 00 48 8b da 4c 8b f1 48 89 94 24 c0 00 00 00 45 33 ff 44 89 7c 24 30 0f 57 c0 0f 11 02 4c 89 7a 10 4c 89 7a 18 41 b8 0f 05 00 00 48 8d 15 ?? ?? ?? 00 48 8b cb } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}