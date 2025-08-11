
rule Trojan_Win64_Latrodectus_YAC_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.YAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 5f 41 5b 44 30 2c 0f 66 0f d9 da 66 0f d9 d0 66 0f eb d3 66 0f 6f d8 66 0f f5 d1 66 0f fe f2 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}