
rule Trojan_Win64_CobaltStrike_JHG_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.JHG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 c8 49 f7 e0 48 c1 ea ?? 48 8d 04 52 48 89 ca 48 01 c0 48 29 c2 0f b6 44 14 ?? 32 04 0e 88 04 0b 48 83 c1 ?? 48 81 f9 ?? ?? ?? ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}