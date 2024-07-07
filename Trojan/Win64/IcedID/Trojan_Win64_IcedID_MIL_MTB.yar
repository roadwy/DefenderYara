
rule Trojan_Win64_IcedID_MIL_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MIL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 ff c0 66 89 44 24 90 01 01 0f b7 44 24 90 01 01 8b 4c 24 90 01 01 83 c1 90 01 01 48 63 c9 48 8b 94 24 90 01 04 8b 0c 8a 0f af c8 8b c1 48 98 48 89 84 24 90 01 04 8b 84 24 90 01 04 89 44 24 90 01 01 48 63 44 24 90 01 01 b9 90 01 04 48 69 c9 90 01 04 48 8b 15 90 01 04 48 33 04 0a 66 89 44 24 90 01 01 44 0f b7 4c 24 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}