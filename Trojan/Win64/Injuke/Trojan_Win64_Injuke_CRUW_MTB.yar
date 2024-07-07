
rule Trojan_Win64_Injuke_CRUW_MTB{
	meta:
		description = "Trojan:Win64/Injuke.CRUW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 74 99 83 e0 90 01 01 33 c2 2b c2 85 c0 74 90 01 01 8b 44 24 74 ff c0 89 44 24 74 eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}