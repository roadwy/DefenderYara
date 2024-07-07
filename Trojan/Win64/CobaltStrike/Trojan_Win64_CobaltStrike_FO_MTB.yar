
rule Trojan_Win64_CobaltStrike_FO_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.FO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d1 c1 e9 90 01 01 81 e2 90 01 04 c1 e2 90 01 01 0b d1 0f ca 43 8d 0c 00 8b c2 41 33 c0 44 8b c1 41 81 f0 90 01 04 85 c0 44 0f 49 c1 03 d2 49 83 ea 90 01 01 75 90 01 01 49 ff c1 41 8a 01 84 c0 0f 85 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}