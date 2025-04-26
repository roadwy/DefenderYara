
rule Trojan_Win64_CobaltStrike_PX_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 04 24 ff c0 89 04 24 48 63 04 24 48 3b 44 24 ?? 73 ?? 48 63 04 24 0f b6 4c 24 ?? 48 8b 54 24 ?? 0f b6 04 02 33 c1 48 63 0c 24 48 8b 54 24 ?? 88 04 0a eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}