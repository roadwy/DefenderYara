
rule Trojan_Win64_CobaltStrike_MKV_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 33 c0 c7 44 24 20 ?? ?? ?? ?? 48 8d 55 ?? 48 8d 4b ?? e8 ?? ?? ?? ?? 8b d3 4c 8d 45 ?? 41 0f b6 ?? 4d 8d 40 ?? 48 63 c2 80 f1 69 48 03 45 ?? ff c2 88 08 81 fa ?? ?? ?? ?? 76 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}