
rule Trojan_Win64_Barys_TTV_MTB{
	meta:
		description = "Trojan:Win64/Barys.TTV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 01 c2 81 c2 00 00 00 8d 42 33 14 30 42 89 94 34 ?? ?? ?? ?? 49 83 c6 04 49 83 fe 43 76 d3 8a 40 44 34 6d 48 8d bc 24 ?? ?? ?? ?? 88 47 44 6a 45 41 5e 4c 89 f1 e8 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}