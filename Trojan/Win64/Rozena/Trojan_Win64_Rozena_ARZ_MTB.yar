
rule Trojan_Win64_Rozena_ARZ_MTB{
	meta:
		description = "Trojan:Win64/Rozena.ARZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c6 c1 ee 18 45 33 84 b2 ?? ?? ?? ?? 0f b6 f6 0f b6 d4 c1 e8 10 45 33 84 b2 ?? ?? ?? ?? 47 33 84 8a ?? ?? ?? ?? 44 0f b6 c8 43 8b 84 8a ?? ?? ?? ?? 45 33 84 92 ?? ?? ?? ?? 44 31 c0 4c 39 db } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}