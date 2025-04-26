
rule Trojan_Win64_CobaltStrike_YBM_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.YBM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 33 c6 01 05 59 f7 02 00 44 0f af 41 78 8b 05 ae f7 02 00 2b 41 40 01 81 a4 00 00 00 48 8b 05 ?? ?? ?? ?? 41 8b d0 c1 ea 18 48 63 88 a8 00 00 00 48 8b 05 ?? ?? ?? ?? 88 14 01 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}