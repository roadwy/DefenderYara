
rule Trojan_Win64_CobaltStrike_FOC_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.FOC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {6d 75 75 75 75 74 65 78 } //1 muuuutex
		$a_03_1 = {48 c7 c1 05 00 00 00 8a 10 80 f2 55 88 10 48 ff c0 e2 f4 48 b8 ?? ?? ?? ?? ?? 00 00 00 48 c7 c1 19 00 00 00 8a 10 80 f2 55 88 10 48 ff c0 e2 f4 48 b8 ?? ?? ?? ?? ?? 00 00 00 48 c7 c1 14 00 00 00 8a 10 80 f2 55 88 10 48 ff c0 e2 f4 48 b8 ?? ?? ?? ?? ?? 00 00 00 48 c7 c1 06 00 00 00 8a 10 80 f2 55 88 10 48 ff c0 e2 f4 } //1
	condition:
		((#a_81_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}