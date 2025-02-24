
rule Trojan_Win64_CobaltStrike_FN_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.FN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 00 31 c3 89 da 8b 85 d8 b0 04 00 48 98 88 54 05 70 83 85 dc b0 04 00 01 83 85 d8 b0 04 00 01 8b 85 d8 b0 04 00 48 98 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_FN_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.FN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {88 01 48 8d 49 ?? ff c0 3d ?? ?? ?? ?? 72 } //1
		$a_03_1 = {41 0f b6 14 18 41 8d 04 12 44 0f b6 d0 42 0f b6 04 11 41 88 04 18 42 88 14 11 41 0f b6 0c 18 48 03 ca 0f b6 c1 0f b6 4c 04 ?? 41 30 49 ff 49 83 eb ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}