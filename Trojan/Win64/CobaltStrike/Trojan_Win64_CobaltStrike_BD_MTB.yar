
rule Trojan_Win64_CobaltStrike_BD_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.BD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 0f b7 ?? 33 d2 66 2b 05 ?? ?? ?? ?? 66 f7 35 ?? ?? ?? ?? 88 06 46 33 d2 43 33 d2 83 c1 02 4f 8b d7 85 d2 75 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}