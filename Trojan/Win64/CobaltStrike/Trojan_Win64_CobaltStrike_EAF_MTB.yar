
rule Trojan_Win64_CobaltStrike_EAF_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.EAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 83 c2 02 48 8b bc 24 ?? ?? ?? ?? 49 83 c1 08 48 8b 9c 24 ?? ?? ?? ?? 4c 8b 9c 24 a0 00 00 00 89 04 91 48 8b 05 3d b2 07 00 48 8b 15 ?? ?? ?? ?? 4c 89 54 24 70 4c 89 4c 24 68 8a 4c 47 01 4b 8d 04 64 30 0c 10 8b 84 24 48 01 00 00 48 8b 54 24 60 41 03 c6 89 84 24 ?? ?? ?? ?? 3d a0 0b 00 00 0f 8f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}