
rule Backdoor_Win64_AdaptixC2_MKA_MTB{
	meta:
		description = "Backdoor:Win64/AdaptixC2.MKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 89 c2 48 8b 05 ?? ?? ?? ?? 48 89 90 90 ?? ?? ?? 00 48 8b 45 f8 ba 44 b1 52 16 48 89 c1 e8 ?? ?? ?? ?? 48 89 c2 48 8b 05 ?? ?? ?? ?? 48 89 90 90 ?? ?? ?? 00 48 8b 45 f8 ba 24 5c 07 90 90 48 89 c1 } //20
		$a_01_1 = {89 d0 c1 f8 1f c1 e8 18 01 c2 0f b6 d2 29 c2 89 55 fc 8b 45 fc 48 63 d0 48 8b 45 20 48 01 d0 0f b6 00 0f b6 d0 8b 45 f8 01 c2 89 d0 } //15
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*15) >=35
 
}