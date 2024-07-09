
rule Trojan_Win64_CobaltStrike_ZE_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ZE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 c1 08 da 44 20 c3 08 cb 89 d9 30 c1 20 d9 44 08 c0 89 d3 30 c3 08 d0 34 01 08 d8 89 cb 80 f3 01 89 c2 80 f2 01 20 d8 08 d3 20 ca 08 c2 89 d9 30 d1 be ?? ?? ?? ?? b8 ?? ?? ?? ?? f6 c1 01 75 05 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_ZE_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.ZE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 2b c1 48 0f af c6 48 03 c8 48 0f af ff 48 8d 04 7f 48 2b c8 49 03 cd 42 0f b6 94 32 ?? ?? ?? ?? 42 32 94 31 ?? ?? ?? ?? 48 8d 04 76 49 8b cd 48 2b c8 48 8b 84 24 ?? ?? ?? ?? 88 14 01 41 ff c4 49 ff c5 49 63 c4 48 3b 84 24 ?? ?? ?? ?? 73 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}