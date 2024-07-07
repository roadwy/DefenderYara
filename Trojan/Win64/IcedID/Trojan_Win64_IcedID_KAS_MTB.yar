
rule Trojan_Win64_IcedID_KAS_MTB{
	meta:
		description = "Trojan:Win64/IcedID.KAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {99 44 8b 8d 90 01 04 41 f7 f9 03 15 90 01 04 03 15 90 01 04 03 15 90 01 04 4c 63 d2 42 0f b6 14 11 41 31 d0 45 88 c3 48 8b 8d 90 01 04 8b 95 90 01 04 2b 15 90 01 04 44 8b 05 90 01 04 44 0f af 05 90 01 04 44 29 c2 44 8b 05 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}