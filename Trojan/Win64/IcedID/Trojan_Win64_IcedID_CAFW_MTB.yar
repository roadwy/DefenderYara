
rule Trojan_Win64_IcedID_CAFW_MTB{
	meta:
		description = "Trojan:Win64/IcedID.CAFW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 63 44 24 50 48 8d ?? ?? ?? ?? ?? 0f b6 04 01 89 84 24 90 90 00 00 00 8b 44 24 50 99 b9 ?? ?? ?? ?? f7 f9 8b c2 48 98 48 8d ?? ?? ?? ?? ?? 0f be 04 01 8b 8c 24 90 90 00 00 00 33 c8 8b c1 48 63 4c 24 50 48 8b 54 24 68 88 04 0a eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}