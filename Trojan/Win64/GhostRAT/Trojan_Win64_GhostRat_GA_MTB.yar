
rule Trojan_Win64_GhostRat_GA_MTB{
	meta:
		description = "Trojan:Win64/GhostRat.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {64 a1 30 00 00 00 53 33 db 89 5c 24 5c 89 5c 24 70 89 5c 24 74 89 5c 24 78 8b 40 0c 8b 40 14 56 57 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}