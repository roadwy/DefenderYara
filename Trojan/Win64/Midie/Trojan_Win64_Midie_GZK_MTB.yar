
rule Trojan_Win64_Midie_GZK_MTB{
	meta:
		description = "Trojan:Win64/Midie.GZK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {b4 1f 4d bf 85 e6 08 f6 9c fa 43 1b 08 1e 32 f9 bf } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}