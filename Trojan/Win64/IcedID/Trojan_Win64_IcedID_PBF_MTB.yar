
rule Trojan_Win64_IcedID_PBF_MTB{
	meta:
		description = "Trojan:Win64/IcedID.PBF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c8 48 8b 83 90 01 04 31 4b 90 01 01 41 8b d0 48 63 8b 90 01 04 c1 ea 10 88 14 01 41 8b d0 ff 83 90 01 04 48 63 8b 90 01 04 48 8b 83 90 01 04 c1 ea 08 88 14 01 ff 83 90 01 04 8b 43 70 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}