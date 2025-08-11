
rule Trojan_Win64_RemcosRAT_KAT_MTB{
	meta:
		description = "Trojan:Win64/RemcosRAT.KAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {65 48 8b 04 25 30 00 00 00 48 8b 50 60 48 85 c9 75 09 48 8b 42 10 e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}