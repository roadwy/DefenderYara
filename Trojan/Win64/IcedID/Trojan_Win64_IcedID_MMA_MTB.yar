
rule Trojan_Win64_IcedID_MMA_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 49 89 44 c9 90 01 01 48 8b 05 90 01 04 0f b6 0d 90 01 04 48 83 c0 90 01 01 48 c1 e0 90 01 01 48 89 0c 18 41 0f b6 03 49 81 34 c1 90 01 04 48 8b 05 90 01 04 48 35 90 01 04 49 f7 34 f9 49 89 04 f9 42 0f b7 44 6d 90 01 01 44 3b c0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}