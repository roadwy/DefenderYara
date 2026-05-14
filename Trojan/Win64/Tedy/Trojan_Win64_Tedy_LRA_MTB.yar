
rule Trojan_Win64_Tedy_LRA_MTB{
	meta:
		description = "Trojan:Win64/Tedy.LRA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 84 0c e8 00 00 00 34 7a 88 84 0c d0 01 00 00 48 8d 49 01 49 83 e8 01 75 ?? 40 88 b4 24 d9 01 00 00 33 d2 41 b8 00 04 00 00 48 8d 8c 24 40 02 00 00 } //30
	condition:
		((#a_03_0  & 1)*30) >=30
 
}