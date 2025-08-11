
rule Trojan_Win64_FatalRAT_GZZ_MTB{
	meta:
		description = "Trojan:Win64/FatalRAT.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff d3 c7 44 24 24 00 00 00 00 31 d2 89 d0 41 89 d0 8b 4c 24 24 41 c1 f8 02 83 e0 3f 41 0f af c0 44 6b c2 0d ff c2 44 31 c0 01 c8 81 fa f4 01 00 00 89 44 24 24 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}