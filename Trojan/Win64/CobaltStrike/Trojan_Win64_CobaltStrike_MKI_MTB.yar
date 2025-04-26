
rule Trojan_Win64_CobaltStrike_MKI_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MKI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c2 41 f6 f7 48 83 fa ?? 74 ?? 0f b6 c0 6b c0 ?? 89 d9 28 c1 30 8c 15 ?? ?? ?? ?? 48 ff c2 fe c3 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}