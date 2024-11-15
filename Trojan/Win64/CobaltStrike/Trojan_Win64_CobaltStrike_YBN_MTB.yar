
rule Trojan_Win64_CobaltStrike_YBN_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.YBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {42 30 8c 0d ?? ?? ?? ?? 41 f7 e8 c6 85 40 21 00 00 00 c1 fa 02 8b c2 c1 e8 ?? 03 d0 8d 04 d2 03 c0 44 2b c0 49 63 c0 0f b6 94 05 f8 00 00 00 42 30 94 0d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}