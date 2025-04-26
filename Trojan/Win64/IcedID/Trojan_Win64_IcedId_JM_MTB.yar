
rule Trojan_Win64_IcedId_JM_MTB{
	meta:
		description = "Trojan:Win64/IcedId.JM!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {88 04 0a e9 31 ff ff ff eb 48 8b c2 48 98 3a e4 74 c8 80 44 24 23 01 c7 04 24 00 00 00 00 eb b4 e9 14 ff ff ff 8b 4c 24 04 33 c8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}