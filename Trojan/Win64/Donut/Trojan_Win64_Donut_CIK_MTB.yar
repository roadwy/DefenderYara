
rule Trojan_Win64_Donut_CIK_MTB{
	meta:
		description = "Trojan:Win64/Donut.CIK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 89 c1 83 c0 01 89 45 fc 48 8b 45 10 48 01 c8 0f b7 08 66 89 4d f6 8b 45 f8 c1 e8 08 8b 4d f8 c1 e1 18 09 c8 0f b7 4d f6 01 c1 8b 45 f8 31 c8 89 45 f8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}