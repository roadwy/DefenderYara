
rule Trojan_Win64_Tedy_GTR_MTB{
	meta:
		description = "Trojan:Win64/Tedy.GTR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {d0 34 b6 39 e3 58 6c 18 22 } //5
		$a_03_1 = {9c ec 28 76 ?? a4 32 44 3a ?? 55 1a 8b } //5
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}