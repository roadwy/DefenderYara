
rule Trojan_Win64_Dridex_PGD_MTB{
	meta:
		description = "Trojan:Win64/Dridex.PGD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 44 24 64 8b 44 24 34 35 07 18 8d 5a 89 84 24 a8 00 00 00 e9 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}