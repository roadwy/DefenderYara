
rule Trojan_Win64_IcedID_HAN_MTB{
	meta:
		description = "Trojan:Win64/IcedID.HAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c8 41 89 c9 41 f7 eb 89 c8 c1 f8 1f 01 ca c1 fa 05 29 c2 b8 3e 00 00 00 0f af d0 41 29 d1 4d 63 c9 47 0f b6 04 08 44 32 04 0b 45 88 04 0a 48 83 c1 01 48 81 f9 9d 0b 00 00 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}