
rule Trojan_Win64_Tedy_GHT_MTB{
	meta:
		description = "Trojan:Win64/Tedy.GHT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {80 74 24 21 32 80 74 24 22 33 80 74 24 23 34 80 74 24 24 35 80 74 24 25 36 80 74 24 26 37 80 74 24 27 38 66 89 4c 24 28 80 f1 39 80 74 24 29 3a 34 3b c6 44 24 20 42 88 44 24 2a 48 8d 44 24 20 88 4c 24 28 0f 1f 44 00 00 49 ff c0 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}
rule Trojan_Win64_Tedy_GHT_MTB_2{
	meta:
		description = "Trojan:Win64/Tedy.GHT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 44 24 70 4e c6 44 24 71 74 c6 44 24 72 46 c6 44 24 73 72 c6 44 24 74 65 c6 44 24 75 65 c6 44 24 76 56 c6 44 24 77 69 c6 44 24 78 72 c6 44 24 79 74 c6 44 24 7a 75 c6 44 24 7b 61 c6 44 24 7c 6c c6 44 24 7d 4d c6 44 24 7e 65 c6 44 24 7f 6d c6 84 24 80 00 00 00 6f c6 84 24 81 00 00 00 72 c6 84 24 82 00 00 00 79 c6 84 24 83 00 00 00 00 48 8d 54 24 70 48 89 f1 ff 15 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}