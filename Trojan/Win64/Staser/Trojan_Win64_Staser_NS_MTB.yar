
rule Trojan_Win64_Staser_NS_MTB{
	meta:
		description = "Trojan:Win64/Staser.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 c0 4c 8d 44 24 90 01 01 4c 89 c7 f3 48 ab 48 8b 3d a8 9f 85 01 44 8b 0f 45 85 c9 0f 85 90 01 04 65 48 8b 04 25 30 00 00 00 48 8b 1d 90 01 04 48 8b 70 08 31 ed 4c 8b 25 90 01 04 eb 16 0f 1f 90 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}