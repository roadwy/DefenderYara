
rule Trojan_Win64_Zapchast_ARR_MTB{
	meta:
		description = "Trojan:Win64/Zapchast.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 c2 83 e2 ?? 0f b6 54 14 5c 41 32 14 04 88 14 03 48 83 c0 ?? 48 39 c6 75 } //14
		$a_03_1 = {31 d2 4c 8d 05 ?? ?? ?? ?? 48 89 d9 66 89 50 } //6
	condition:
		((#a_03_0  & 1)*14+(#a_03_1  & 1)*6) >=20
 
}