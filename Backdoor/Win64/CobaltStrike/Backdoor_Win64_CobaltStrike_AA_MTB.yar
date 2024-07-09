
rule Backdoor_Win64_CobaltStrike_AA_MTB{
	meta:
		description = "Backdoor:Win64/CobaltStrike.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {55 48 89 e5 48 83 ec 50 c7 45 e4 ?? ?? ?? ?? 8b 05 ?? 2a 03 00 89 c0 41 b9 ?? ?? ?? ?? 4c 8d 05 ?? ?? 03 00 48 89 c2 48 8d 0d ?? 29 03 00 e8 ?? ff ff ff 48 8d 0d ?? ?? 03 00 48 8b 05 ?? ?? 03 } //10
		$a_00_1 = {55 48 89 e5 48 83 ec 10 48 89 4d 10 48 89 55 18 4c 89 45 20 4c 89 4d 28 c7 45 fc } //10
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10) >=20
 
}