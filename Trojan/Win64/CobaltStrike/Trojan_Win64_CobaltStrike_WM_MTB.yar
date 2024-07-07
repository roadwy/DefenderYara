
rule Trojan_Win64_CobaltStrike_WM_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.WM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 47 50 41 8b d2 69 88 90 01 08 48 8b 47 90 01 01 44 03 c1 41 8b c8 d3 ea 8a 48 90 01 01 48 8b 47 90 01 01 80 f1 d0 22 d1 48 63 8f 90 01 04 88 14 01 01 b7 90 01 04 48 8b 47 90 01 01 48 39 07 76 90 01 01 48 8b 47 90 01 01 48 8b 88 90 01 04 48 81 c1 90 01 04 48 31 4f 90 01 01 48 8b 87 90 01 04 48 05 90 01 04 48 09 87 90 01 04 45 85 c0 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}