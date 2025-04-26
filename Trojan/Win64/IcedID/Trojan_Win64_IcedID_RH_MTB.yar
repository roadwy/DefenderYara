
rule Trojan_Win64_IcedID_RH_MTB{
	meta:
		description = "Trojan:Win64/IcedID.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 c8 c1 f8 1f 29 c2 89 d0 6b c0 ?? 29 c1 89 c8 48 63 d0 48 8b 45 e8 48 01 d0 0f b6 00 44 31 c8 41 88 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}