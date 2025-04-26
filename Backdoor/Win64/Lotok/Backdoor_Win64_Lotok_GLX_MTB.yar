
rule Backdoor_Win64_Lotok_GLX_MTB{
	meta:
		description = "Backdoor:Win64/Lotok.GLX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 8b f5 0f b7 43 14 48 8d 0d ?? ?? ?? ?? 48 03 c6 4c 89 6c 24 20 44 8b 44 18 2c 8b 54 18 24 4c 03 c1 48 8b 4c 24 68 49 03 d6 44 8b 4c 18 28 ff 15 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}