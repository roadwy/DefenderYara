
rule Trojan_Win64_Zusy_GNM_MTB{
	meta:
		description = "Trojan:Win64/Zusy.GNM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {80 32 f4 9a b2 ab 02 3e e4 97 12 1e 25 f4 65 8e ce 8a 56 40 f7 62 0c 95 5b 61 e1 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}