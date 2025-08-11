
rule Trojan_Win64_Latrodectus_DL_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {45 29 d3 41 c1 e2 04 45 0f af d8 45 01 da 41 83 c2 08 41 c1 ea 04 41 20 c3 41 88 0c 08 66 41 09 c2 48 ff c1 } //5
		$a_01_1 = {48 ff c2 41 30 db 48 81 fa } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}