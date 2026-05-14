
rule Trojan_Win64_Tedy_LRB_MTB{
	meta:
		description = "Trojan:Win64/Tedy.LRB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_01_0 = {4d 89 d1 49 83 c9 02 46 0f be 0c 09 41 c1 e1 10 49 83 ca 01 46 0f be 14 11 41 c1 e2 08 45 31 d1 } //20
		$a_01_1 = {46 0f be 14 89 46 0f be 5c 89 01 41 c1 e3 08 45 09 d3 46 0f be 54 89 02 41 c1 e2 10 42 0f b6 74 89 03 c1 e6 18 44 09 d6 44 09 de } //10
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}