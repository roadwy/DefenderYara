
rule Trojan_Win64_CobaltStrike_ZA_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.ZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 0f b6 cc 49 89 cc 48 01 d9 0f b6 01 41 01 c1 45 0f b6 d1 4d 89 d1 49 01 da 45 0f b6 1a 44 88 19 41 88 02 02 01 0f b6 c0 0f b6 44 04 90 01 01 41 30 00 49 83 c0 90 01 01 49 39 d0 75 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}