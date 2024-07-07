
rule Trojan_Win64_IcedId_AID_MTB{
	meta:
		description = "Trojan:Win64/IcedId.AID!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b c2 6b c8 90 01 01 41 8b c3 f7 e9 03 d1 c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 d0 6b c2 90 01 01 2b c8 41 8b c3 83 c1 90 01 01 f7 e9 03 d1 c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 d0 6b c2 90 01 01 2b c8 41 88 09 49 ff c1 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}