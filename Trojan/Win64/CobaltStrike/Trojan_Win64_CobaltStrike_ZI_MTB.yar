
rule Trojan_Win64_CobaltStrike_ZI_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ZI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 c3 48 8d 0d ?? ?? ?? ?? e8 a7 ab 00 00 01 d8 31 45 ?? 8b 55 ?? 48 8b 45 ?? 48 01 d0 0f b6 00 84 c0 0f 85 } //1
		$a_03_1 = {01 d8 66 89 45 ?? 0f b7 45 ?? 8b 55 ?? c1 ca ?? 8d 1c 10 48 8d 0d ?? ?? ?? ?? e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}