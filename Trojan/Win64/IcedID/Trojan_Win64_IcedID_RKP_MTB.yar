
rule Trojan_Win64_IcedID_RKP_MTB{
	meta:
		description = "Trojan:Win64/IcedID.RKP!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c8 8b c1 3a c0 74 01 c3 48 63 0c 24 48 8b 54 24 30 eb 0b 8b 44 24 38 39 04 24 7d 0a eb 43 88 04 0a e9 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}