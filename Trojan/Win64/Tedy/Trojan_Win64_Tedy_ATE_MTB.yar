
rule Trojan_Win64_Tedy_ATE_MTB{
	meta:
		description = "Trojan:Win64/Tedy.ATE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 0f b6 08 49 83 c0 01 31 d9 c1 eb 08 0f b6 c9 33 1c 8a 4c 39 c6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}