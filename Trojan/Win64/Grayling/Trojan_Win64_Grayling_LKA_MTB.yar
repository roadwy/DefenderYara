
rule Trojan_Win64_Grayling_LKA_MTB{
	meta:
		description = "Trojan:Win64/Grayling.LKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 e8 08 88 84 24 e1 01 00 00 8b c1 c1 e8 10 45 8d 41 06 88 84 24 e2 01 00 00 0f b6 44 24 22 88 84 24 e4 01 00 00 0f b7 44 24 22 c1 e9 18 66 c1 e8 08 88 8c 24 e3 01 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}