
rule Trojan_Win64_Etset_GVA_MTB{
	meta:
		description = "Trojan:Win64/Etset.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4d 89 c2 66 2d c1 60 0f b6 c0 31 4d e4 29 55 e4 48 33 45 d2 48 ff 04 24 48 83 3c 24 07 7e } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}