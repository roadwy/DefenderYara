
rule Trojan_Win64_CobaltStrike_PKH_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PKH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 63 c1 0f b6 0c 04 41 8d 41 ?? 41 30 0a 25 ?? ?? ?? ?? 7d ?? ff c8 0d ?? ?? ?? ?? ff c0 49 ff c2 44 8b c8 48 83 ea ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}