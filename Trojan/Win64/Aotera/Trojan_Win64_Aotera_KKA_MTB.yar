
rule Trojan_Win64_Aotera_KKA_MTB{
	meta:
		description = "Trojan:Win64/Aotera.KKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c1 44 0f b6 44 06 10 41 83 f0 42 44 88 44 06 10 ff c1 3b d1 } //20
	condition:
		((#a_01_0  & 1)*20) >=20
 
}