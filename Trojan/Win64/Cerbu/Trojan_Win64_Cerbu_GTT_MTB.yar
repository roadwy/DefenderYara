
rule Trojan_Win64_Cerbu_GTT_MTB{
	meta:
		description = "Trojan:Win64/Cerbu.GTT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 f0 13 20 b3 ?? ff 00 18 a5 ?? ?? ?? ?? 48 08 ed 89 ba ?? ?? ?? ?? f7 e3 01 00 00 00 51 32 d6 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}