
rule Trojan_Win64_Beacon_RDA_MTB{
	meta:
		description = "Trojan:Win64/Beacon.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 e2 03 8a 54 15 00 41 32 14 04 88 14 03 48 ff c0 39 f8 89 c2 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}