
rule Trojan_Win64_Poolinject_PGP_MTB{
	meta:
		description = "Trojan:Win64/Poolinject.PGP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 0f ef 4d f7 41 8b c8 66 48 0f 7e c8 48 89 75 07 48 89 7d 0f 66 0f ef 45 07 66 0f 7f 45 d7 66 0f 7f 4d c7 0f be d0 84 c0 74 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}