
rule Trojan_Win64_CobaltStrike_XY_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.XY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 8d 44 24 28 48 89 da b9 68 00 00 00 4c 8d 4b 08 49 29 d8 eb 07 66 90 41 0f b6 0c 10 88 0a 48 83 c2 01 49 39 d1 75 f0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}