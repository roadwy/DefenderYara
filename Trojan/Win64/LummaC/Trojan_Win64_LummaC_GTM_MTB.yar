
rule Trojan_Win64_LummaC_GTM_MTB{
	meta:
		description = "Trojan:Win64/LummaC.GTM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 30 c0 41 89 d8 41 20 c0 30 d8 44 08 c0 } //5
		$a_03_1 = {0f 45 c6 84 db ba ?? ?? ?? ?? 0f 45 c2 48 89 7d } //5
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}