
rule Trojan_Win64_CobaltStrike_YAD_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.YAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4a 60 0f af c8 89 4a 60 8b 05 a5 63 04 00 48 8b 0d d6 63 04 00 41 31 04 0e 49 83 c6 04 44 8b 0d b7 63 04 00 4c 8b 05 f8 62 04 00 41 81 c1 5c 49 ed ff 8b 15 d3 63 04 00 44 03 ca } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_Win64_CobaltStrike_YAD_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.YAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 83 94 00 00 00 8b 8b 20 01 00 00 ff c1 0f af c1 89 83 94 00 00 00 48 8b 05 90 01 04 8b 0c 02 33 4b 6c 48 8b 83 c8 00 00 00 89 0c 02 48 83 c2 04 48 8b 05 90 01 04 8b 88 c0 00 00 00 81 c1 73 81 e0 ff 03 4b 1c 09 8b 90 90 00 00 00 8b 83 90 90 00 00 00 83 f0 01 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}