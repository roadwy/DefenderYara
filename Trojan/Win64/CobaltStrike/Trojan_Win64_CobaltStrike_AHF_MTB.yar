
rule Trojan_Win64_CobaltStrike_AHF_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AHF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 03 c1 e1 ?? 0b c8 0f b6 43 ff c1 e1 ?? 0b c8 0f b6 43 ?? 89 4c 24 30 } //30
		$a_03_1 = {44 8b c5 c1 e1 ?? 41 c1 e8 ?? 44 33 c1 8d 8e ?? ?? ?? ?? 48 c1 e9 ?? 44 03 c5 83 e1 ?? 41 8b 14 8c } //20
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}