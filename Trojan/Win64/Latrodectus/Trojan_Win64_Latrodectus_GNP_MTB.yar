
rule Trojan_Win64_Latrodectus_GNP_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.GNP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 e9 48 ff c9 48 29 f9 48 31 f7 48 83 c0 ?? 0f 57 c3 41 d1 e8 49 d1 ef 41 d1 e8 49 83 e1 ?? 41 83 e0 ?? 48 63 d0 48 63 c1 0f 28 ce 0f 28 f1 0f 28 d6 66 48 0f 7e d0 41 5f 41 5e 41 5d 41 5c 41 5b 41 5a 41 59 41 58 5f 5e 5a 59 5b 58 41 88 0c 08 48 ff c1 48 83 f9 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}