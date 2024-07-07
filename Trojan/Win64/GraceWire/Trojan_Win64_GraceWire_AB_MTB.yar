
rule Trojan_Win64_GraceWire_AB_MTB{
	meta:
		description = "Trojan:Win64/GraceWire.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {48 3d 91 05 00 00 73 79 48 63 84 24 90 01 04 48 8d 0d 90 01 04 8b 04 81 89 84 24 90 01 04 8b 05 90 01 04 8b 8c 24 90 01 04 33 c8 8b c1 89 84 24 90 01 04 8b 84 24 90 01 04 c1 c0 07 89 84 24 90 01 04 8b 05 90 01 04 8b 8c 24 90 01 04 33 c8 8b c1 89 84 24 90 01 04 48 63 84 24 90 01 04 48 8b 8c 24 90 01 04 8b 94 24 90 01 04 89 14 81 e9 67 ff ff ff 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}