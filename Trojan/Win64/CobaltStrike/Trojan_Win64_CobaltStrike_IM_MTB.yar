
rule Trojan_Win64_CobaltStrike_IM_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.IM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8d 70 01 8a 94 04 ?? ?? ?? ?? 32 94 04 ?? ?? ?? ?? 89 d1 f6 d9 08 d1 f6 d1 c0 e9 ?? e8 ?? ?? ?? ?? 20 c3 48 89 f0 eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}