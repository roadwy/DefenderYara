
rule Trojan_Win64_Tedy_AB_MTB{
	meta:
		description = "Trojan:Win64/Tedy.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {45 89 c3 41 81 f3 ff ff ff ff 41 81 e3 14 d1 28 6f 41 81 e1 ff ff ff ff 44 09 d2 45 09 cb 44 31 da 83 f2 ff 41 89 c1 41 31 d1 41 21 c1 89 c2 83 f2 ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}