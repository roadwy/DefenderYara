
rule Trojan_Win64_IcedID_LD_MTB{
	meta:
		description = "Trojan:Win64/IcedID.LD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 29 c2 8b 85 ?? ?? ?? ?? 0f af 85 ?? ?? ?? ?? 0f af 85 ?? ?? ?? ?? 48 98 48 29 c2 48 89 d0 0f b6 84 05 ?? ?? ?? ?? 44 31 c8 41 88 00 48 83 85 ?? ?? ?? ?? ?? 48 8b 85 ?? ?? ?? ?? 48 39 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}