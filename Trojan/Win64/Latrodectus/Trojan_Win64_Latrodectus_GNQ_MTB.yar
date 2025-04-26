
rule Trojan_Win64_Latrodectus_GNQ_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.GNQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 30 14 0f c4 41 7d 6f d0 48 ff c1 c4 41 1d fe e3 48 89 c8 c4 43 1d 0f e4 ?? 48 81 f9 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}