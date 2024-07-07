
rule Trojan_Win64_IcedID_YE_MTB{
	meta:
		description = "Trojan:Win64/IcedID.YE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 8b 84 24 90 01 04 e9 90 01 04 33 c0 48 90 01 06 5f e9 90 01 04 8b 84 24 90 01 04 39 44 24 90 01 01 73 90 01 01 48 90 01 04 e9 90 01 04 48 90 01 04 88 04 0a e9 90 01 04 48 90 01 04 e9 90 01 04 ff c0 89 44 24 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}