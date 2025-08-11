
rule Trojan_Win64_Tedy_WIV_MTB{
	meta:
		description = "Trojan:Win64/Tedy.WIV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 2b c6 41 8b c0 c1 e8 18 32 c1 88 85 ?? 02 00 00 41 8b c0 c1 e8 10 32 c1 88 85 ?? 02 00 00 41 8b c0 c1 e8 08 32 c1 88 85 ?? 02 00 00 44 32 c1 44 88 85 43 02 00 00 33 c0 0f 57 c9 f3 0f 7f 8d 50 02 00 00 48 89 85 60 02 00 00 88 4c 24 50 4c 8d 44 24 50 33 d2 48 8d 8d 50 02 00 00 e8 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}