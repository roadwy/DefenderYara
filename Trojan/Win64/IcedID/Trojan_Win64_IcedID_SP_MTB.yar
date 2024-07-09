
rule Trojan_Win64_IcedID_SP_MTB{
	meta:
		description = "Trojan:Win64/IcedID.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 00 44 ?? ?? 41 ?? ?? 83 45 ?? ?? 8b 45 ?? 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 0f af d1 8b 4d ?? 29 d1 8b 15 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}