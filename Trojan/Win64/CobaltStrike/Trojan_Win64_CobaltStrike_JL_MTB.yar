
rule Trojan_Win64_CobaltStrike_JL_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.JL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 c2 83 e2 ?? 0f b6 14 17 32 14 03 41 88 54 05 ?? 48 83 c0 ?? 49 39 c6 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win64_CobaltStrike_JL_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.JL!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {80 f2 1f 41 fe c0 88 14 01 41 0f b6 c8 42 8a 54 09 01 84 d2 } //2
		$a_01_1 = {41 8b 41 24 49 03 c0 8b ca 0f b7 14 48 41 8b 49 1c 49 03 c8 8b 34 91 49 03 f0 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=2
 
}