
rule Trojan_Win64_CobaltStrike_WM_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.WM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 47 50 41 8b d2 69 88 ?? ?? ?? ?? ?? ?? ?? ?? 48 8b 47 ?? 44 03 c1 41 8b c8 d3 ea 8a 48 ?? 48 8b 47 ?? 80 f1 d0 22 d1 48 63 8f ?? ?? ?? ?? 88 14 01 01 b7 ?? ?? ?? ?? 48 8b 47 ?? 48 39 07 76 ?? 48 8b 47 ?? 48 8b 88 ?? ?? ?? ?? 48 81 c1 ?? ?? ?? ?? 48 31 4f ?? 48 8b 87 ?? ?? ?? ?? 48 05 ?? ?? ?? ?? 48 09 87 ?? ?? ?? ?? 45 85 c0 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}