
rule Trojan_Win64_Zbot_GVA_MTB{
	meta:
		description = "Trojan:Win64/Zbot.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 c2 83 e2 01 83 fa 01 19 d2 83 e2 3e 83 ea 7b 30 14 07 48 ff c0 90 13 39 c1 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}