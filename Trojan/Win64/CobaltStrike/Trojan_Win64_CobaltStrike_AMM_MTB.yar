
rule Trojan_Win64_CobaltStrike_AMM_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AMM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {45 0f b6 c0 46 0f b6 84 04 ?? ?? 00 00 44 30 04 ?? 48 ff c0 49 39 c4 75 } //4
		$a_03_1 = {89 c8 31 d2 f7 ?? 4c 8d 41 01 41 0f b6 04 17 88 84 0c } //1
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*1) >=5
 
}