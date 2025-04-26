
rule Trojan_Win64_CobaltStrike_CS_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 63 c2 48 8d 8d ?? ?? ?? ?? 48 03 c8 0f b6 01 41 88 04 30 44 88 09 41 0f b6 04 30 41 03 c1 0f b6 c0 0f b6 8c 05 ?? ?? ?? ?? 41 30 0a 49 ff c2 49 83 eb ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}