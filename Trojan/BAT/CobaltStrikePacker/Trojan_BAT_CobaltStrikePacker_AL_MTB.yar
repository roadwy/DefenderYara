
rule Trojan_BAT_CobaltStrikePacker_AL_MTB{
	meta:
		description = "Trojan:BAT/CobaltStrikePacker.AL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 0a 16 9a 72 ?? ?? ?? 70 18 17 8d ?? ?? 00 01 25 16 72 ?? ?? ?? 70 a2 28 ?? ?? 00 0a 28 ?? ?? 00 ?? 28 ?? ?? 00 0a 72 ?? ?? ?? 70 18 18 8d ?? ?? 00 01 25 16 16 8c ?? ?? 00 01 a2 25 17 19 8d ?? ?? 00 01 25 16 28 ?? ?? 00 06 16 9a a2 25 17 28 ?? ?? 00 06 17 9a a2 25 18 72 ?? ?? ?? 70 a2 a2 28 ?? ?? 00 ?? 26 38 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}