
rule Trojan_Win64_CobaltStrike_AZP_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AZP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 fd 66 0f 6e e5 66 0f 70 e4 ?? 66 0f 6f ec 66 0f db e8 66 0f db e1 66 0f 76 e1 66 0f db e2 66 0f 76 e8 66 0f db eb 66 0f ef ec c1 ed 08 66 0f 70 e5 ?? 66 0f ef e5 66 0f 70 ec 55 66 0f ef ec 66 0f 7e ef 31 ef 0f b6 2e 48 ff c6 40 84 ed 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}