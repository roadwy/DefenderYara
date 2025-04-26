
rule Trojan_Win64_Injuke_CRUV_MTB{
	meta:
		description = "Trojan:Win64/Injuke.CRUV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 44 24 18 8b 44 24 08 99 83 e0 ?? 33 c2 2b c2 85 c0 74 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}