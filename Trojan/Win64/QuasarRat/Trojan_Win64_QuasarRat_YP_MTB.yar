
rule Trojan_Win64_QuasarRat_YP_MTB{
	meta:
		description = "Trojan:Win64/QuasarRat.YP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 39 ca 74 3c 4c 8b 04 08 4d 89 c1 49 c1 e9 08 4d 31 c1 49 21 f1 4d 31 c8 49 c1 e1 08 4d 31 c1 4d 89 c8 49 c1 e8 04 4d 31 c8 4d 21 f8 4d 31 c1 49 c1 e0 04 4d 31 c8 4c 89 04 08 48 83 c1 08 eb bf } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}