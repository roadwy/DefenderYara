
rule Trojan_Win64_Marte_KAD_MTB{
	meta:
		description = "Trojan:Win64/Marte.KAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 ca 0f b7 c0 49 83 c2 90 01 01 c1 e2 90 01 01 01 d0 01 c1 41 0f b7 42 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}