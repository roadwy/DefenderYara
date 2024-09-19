
rule Trojan_Win64_CobaltStrike_PV_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b c6 41 ff c1 4d 8d 52 ?? 48 f7 e1 48 c1 ea ?? 48 8d 04 92 48 c1 e0 ?? 48 2b c8 48 03 cb 0f b6 44 0c ?? 43 32 44 13 ?? 41 88 42 ?? 41 81 f9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}