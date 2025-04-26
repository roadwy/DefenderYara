
rule Trojan_Win64_CobaltStrike_OPP_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.OPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d1 d1 ea 8d 04 09 33 d0 8d 04 09 41 23 d3 33 d0 8b ca c1 e9 02 8d 04 95 ?? ?? ?? ?? 33 c8 8d 04 95 ?? ?? ?? ?? 81 e1 33 33 33 33 33 c8 } //1
		$a_03_1 = {8b c2 41 33 c0 44 8b c1 41 81 f0 25 ?? ?? ?? 85 c0 44 0f 49 c1 03 d2 49 83 ea 01 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}