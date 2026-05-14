
rule Trojan_Win64_Lazy_MKG_MTB{
	meta:
		description = "Trojan:Win64/Lazy.MKG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 51 70 49 89 53 08 48 8b 51 68 49 89 53 10 48 8b 54 24 40 49 89 53 18 48 8b 59 58 49 89 5b 20 48 8b 59 40 49 89 5b 28 } //15
		$a_01_1 = {90 be 01 00 00 00 87 72 10 48 8b 05 b6 07 4b 00 48 8b 0d df 07 4b 00 48 8b 1d b0 07 4b 00 48 8b 3d d9 07 4b } //10
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*10) >=25
 
}