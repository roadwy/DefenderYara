
rule Trojan_Win64_Lazy_AP_MTB{
	meta:
		description = "Trojan:Win64/Lazy.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f 95 c0 0f 94 c1 83 3d 86 0b 04 00 09 0f 9f c2 30 d1 89 d3 20 c3 30 c2 08 da 89 c8 30 d0 bd } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}