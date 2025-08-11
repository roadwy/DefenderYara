
rule Trojan_Win64_Zusy_GF_MTB{
	meta:
		description = "Trojan:Win64/Zusy.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 8b c1 4d 85 c9 74 22 66 66 0f 1f 84 00 00 00 00 00 48 8b 08 48 83 c0 08 48 89 0a 48 83 c2 08 49 83 e9 01 75 ec 8b 4c 24 48 41 83 e0 07 74 26 48 2b d0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}