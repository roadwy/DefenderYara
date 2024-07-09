
rule Trojan_Win64_IcedID_SL_MTB{
	meta:
		description = "Trojan:Win64/IcedID.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {99 f7 7c 24 ?? eb ?? 89 44 24 ?? 8b 04 24 eb ?? 48 ?? ?? ?? c7 04 24 ?? ?? ?? ?? eb ?? eb ?? 8b 4c 24 ?? 33 c8 eb ?? 48 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}