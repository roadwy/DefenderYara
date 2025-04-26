
rule Trojan_Win64_IcedID_ROM_MTB{
	meta:
		description = "Trojan:Win64/IcedID.ROM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f af c2 01 c8 48 63 d0 48 8b 45 ?? 48 01 d0 0f b6 00 44 31 c8 41 88 00 83 45 fc ?? 8b 45 ?? 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af d1 8b 4d ?? 29 d1 8b 15 ?? ?? ?? ?? 01 ca 39 d0 0f 82 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}