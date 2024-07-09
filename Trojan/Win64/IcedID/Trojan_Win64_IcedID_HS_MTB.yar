
rule Trojan_Win64_IcedID_HS_MTB{
	meta:
		description = "Trojan:Win64/IcedID.HS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 63 c8 49 8b c6 49 83 c2 ?? 48 f7 e1 48 c1 ea ?? 48 6b c2 ?? 48 2b c8 0f b6 44 0d ?? 41 30 04 18 48 ff ce } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}