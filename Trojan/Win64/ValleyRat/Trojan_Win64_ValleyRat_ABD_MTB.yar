
rule Trojan_Win64_ValleyRat_ABD_MTB{
	meta:
		description = "Trojan:Win64/ValleyRat.ABD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 c2 83 e2 07 0f b6 54 14 ?? 41 30 54 05 00 48 83 c0 01 48 39 f0 } //5
		$a_01_1 = {44 30 20 44 30 60 01 48 83 c0 02 49 39 c6 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}