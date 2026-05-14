
rule Trojan_Win64_Jalapeno_ARR_MTB{
	meta:
		description = "Trojan:Win64/Jalapeno.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 06 16 18 28 ?? ?? 00 0a 03 28 ?? ?? ?? ?? 16 06 18 18 } //15
		$a_03_1 = {2d 08 06 11 08 6f ?? ?? ?? ?? 11 05 17 58 13 05 11 05 11 04 8e 69 32 8c } //5
	condition:
		((#a_03_0  & 1)*15+(#a_03_1  & 1)*5) >=20
 
}