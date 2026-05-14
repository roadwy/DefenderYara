
rule Trojan_Win64_Midie_GVK_MTB{
	meta:
		description = "Trojan:Win64/Midie.GVK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 0c 3a 8b c2 83 e0 07 c0 c1 02 32 88 ?? ?? ?? ?? f6 d1 80 c1 5a 88 0c 3a 42 3b d6 7c e2 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}