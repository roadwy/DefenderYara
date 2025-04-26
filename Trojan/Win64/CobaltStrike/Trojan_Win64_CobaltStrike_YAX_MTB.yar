
rule Trojan_Win64_CobaltStrike_YAX_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.YAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 c1 e0 05 48 8d 04 91 4c 29 c0 0f b6 84 04 ?? ?? ?? ?? 48 8d 15 55 5e 08 00 32 04 0a 48 8b 94 24 c8 05 00 00 88 04 0a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}