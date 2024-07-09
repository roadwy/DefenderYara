
rule Trojan_Win64_CobaltStrike_TM_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.TM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b cd f7 ed d1 fa 8b c2 c1 e8 ?? 03 d0 8d 04 92 2b c8 48 63 c1 42 8a 84 28 ?? ?? ?? ?? 42 32 44 37 ?? 41 88 06 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}