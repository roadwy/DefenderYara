
rule Trojan_Win64_CobaltStrike_HZP_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.HZP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 fe c1 45 0f b6 c9 4b 8d 14 8e 44 8b 42 08 43 8d 04 03 44 0f b6 d8 43 8b 4c 9e ?? 89 4a 08 47 89 44 9e ?? 44 02 c1 41 0f b6 c0 41 0f b6 4c 86 ?? 41 30 0a 4d 8d 52 01 48 83 eb 01 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}