
rule Trojan_Win64_CobaltStrike_MKVD_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MKVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 83 f8 0d 49 63 c8 48 8b d3 4d 8d 49 ?? 48 0f 45 d0 48 03 4d ?? 41 ff c0 0f b6 44 14 ?? 41 32 41 ?? 88 01 48 8d 42 ?? 41 81 f8 ?? ?? ?? ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}