
rule Trojan_Win64_CobaltStrike_AV_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {f6 0f b6 14 31 01 d0 31 d2 f7 35 ?? ?? ?? ?? 29 fa 29 fa 48 63 d2 8a 04 11 43 30 04 17 e9 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}