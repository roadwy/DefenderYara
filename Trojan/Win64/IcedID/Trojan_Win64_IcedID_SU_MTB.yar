
rule Trojan_Win64_IcedID_SU_MTB{
	meta:
		description = "Trojan:Win64/IcedID.SU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 04 24 eb ?? 48 ?? ?? ?? c7 04 24 ?? ?? ?? ?? eb ?? eb ?? 8b 4c 24 ?? 33 c8 eb ?? ?? f7 7c 24 ?? eb ?? 89 54 24 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}