
rule Trojan_Win64_CobaltStrike_IV_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.IV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 63 c2 48 8d 8c 24 ?? ?? ?? ?? 48 03 c8 0f b6 01 41 88 04 30 44 88 09 41 0f b6 0c 30 49 03 c9 0f b6 c1 0f b6 8c 04 ?? ?? ?? ?? 41 30 0a 49 ff c2 49 83 eb ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}