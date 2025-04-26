
rule Trojan_Win64_Fabookie_EN_MTB{
	meta:
		description = "Trojan:Win64/Fabookie.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 0f b6 01 80 c0 0c 48 83 c1 01 48 33 d2 4c 0f b6 c0 41 83 e8 01 89 d0 41 3b c0 7f 13 41 83 c0 01 48 63 d0 80 04 11 0b 83 c0 01 41 3b c0 75 f1 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}