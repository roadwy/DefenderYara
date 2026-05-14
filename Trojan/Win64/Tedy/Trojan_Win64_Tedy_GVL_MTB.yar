
rule Trojan_Win64_Tedy_GVL_MTB{
	meta:
		description = "Trojan:Win64/Tedy.GVL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8d 14 01 83 e2 07 0f b6 14 13 30 50 01 48 83 c0 01 4c 39 d0 75 e9 4c 89 c9 4c 89 44 24 20 4c 89 c2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}