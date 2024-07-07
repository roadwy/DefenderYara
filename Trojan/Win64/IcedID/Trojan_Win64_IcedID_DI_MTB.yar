
rule Trojan_Win64_IcedID_DI_MTB{
	meta:
		description = "Trojan:Win64/IcedID.DI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c8 f7 ea 8d 04 0a c1 f8 90 01 01 89 c2 89 c8 c1 f8 1f 29 c2 89 d0 6b c0 90 01 01 29 c1 89 c8 48 98 4c 01 d0 0f b6 00 44 31 c8 41 88 00 83 85 90 01 04 01 8b 85 90 01 04 3b 85 90 01 04 7c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}