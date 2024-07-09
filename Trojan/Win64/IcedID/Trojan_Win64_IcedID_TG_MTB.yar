
rule Trojan_Win64_IcedID_TG_MTB{
	meta:
		description = "Trojan:Win64/IcedID.TG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 63 0c 24 48 8b 94 24 ?? ?? ?? ?? e9 ?? ?? ?? ?? 0f b6 04 01 8b 8c 24 ?? ?? ?? ?? eb 00 33 c8 8b c1 eb dc } //1
		$a_00_1 = {88 04 0a e9 } //1
		$a_00_2 = {4c 6a 61 73 6b 64 61 73 73 64 } //1 Ljaskdassd
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}