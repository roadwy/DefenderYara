
rule Trojan_Win64_CobaltStrike_AJ_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b c2 89 44 24 ?? 8b 04 24 48 8b 4c 24 ?? 0f b6 04 01 8b 4c 24 ?? 48 8b 54 24 ?? 0f b6 0c 0a 33 c1 8b 0c 24 48 8b 54 24 ?? 88 04 0a 8b 04 24 48 8b 4c 24 ?? 0f b6 04 01 03 44 24 ?? 8b 0c 24 48 8b 54 24 ?? 88 04 0a eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_AJ_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.AJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 03 c0 41 02 10 88 54 24 ?? 41 0f b6 08 0f b6 c2 48 8d 54 24 ?? 48 03 d0 0f b6 02 41 88 00 88 0a 0f b6 54 24 ?? 44 0f b6 44 24 ?? 0f b6 4c 14 ?? 42 02 4c 04 ?? 0f b6 c1 0f b6 4c 04 ?? 42 32 4c 0b 0f 41 88 49 ff 48 83 ef 01 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win64_CobaltStrike_AJ_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.AJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 0f af c0 89 43 ?? 48 8b 83 ?? ?? ?? ?? 88 14 01 48 63 8b ?? ?? ?? ?? 8d 41 ?? 89 83 ?? ?? ?? ?? 8b 43 ?? 2d ?? ?? ?? ?? 0f af 43 ?? 89 43 ?? 48 8b 83 ?? ?? ?? ?? 44 88 4c 01 ?? b8 ?? ?? ?? ?? 2b 83 ?? ?? ?? ?? ff 83 ?? ?? ?? ?? 89 83 ?? ?? ?? ?? 49 81 fb ?? ?? ?? ?? 0f 8c } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}