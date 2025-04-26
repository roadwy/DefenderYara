
rule Trojan_Win64_Zegost_SAG_MTB{
	meta:
		description = "Trojan:Win64/Zegost.SAG!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {e8 f7 04 00 00 48 83 c4 28 e9 09 10 ff ff cc cc 40 53 48 83 ec 20 48 8b d9 33 c9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}