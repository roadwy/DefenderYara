
rule Trojan_Win64_Latrodectus_DG_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.DG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 31 d2 49 f7 f0 45 8a 14 11 44 30 14 0f 48 ff c1 48 89 c8 48 81 f9 a5 d3 03 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}