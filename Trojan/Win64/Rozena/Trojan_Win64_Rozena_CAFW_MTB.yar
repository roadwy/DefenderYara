
rule Trojan_Win64_Rozena_CAFW_MTB{
	meta:
		description = "Trojan:Win64/Rozena.CAFW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 b9 10 00 00 00 49 89 c8 48 89 c1 e8 ?? ?? ?? ?? 48 8b 85 e0 03 01 00 41 b9 40 00 00 00 41 b8 00 10 00 00 48 89 c2 b9 00 00 00 00 48 8b 05 75 6a 01 00 ff ?? 48 89 85 d8 03 01 00 48 8b 05 05 6a 01 00 ff ?? 48 89 c1 4c 8b 85 e0 03 01 00 48 8d 55 b0 48 8b 85 d8 03 01 00 48 c7 44 24 20 00 00 00 00 4d 89 c1 49 89 d0 48 89 c2 48 8b 05 4d 6a 01 00 ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}