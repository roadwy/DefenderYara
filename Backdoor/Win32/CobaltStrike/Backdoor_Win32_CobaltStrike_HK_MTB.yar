
rule Backdoor_Win32_CobaltStrike_HK_MTB{
	meta:
		description = "Backdoor:Win32/CobaltStrike.HK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c7 8b b5 [0-04] 83 e0 [0-01] 0f b6 44 05 d8 32 87 [0-04] 83 c7 06 88 04 31 8b c6 8b 8d [0-04] 83 e0 [0-01] 0f b6 44 05 d8 32 86 [0-04] 83 c6 06 88 84 0d [0-04] 83 c1 06 89 8d [0-04] 89 b5 [0-04] 81 fa [0-04] 0f 8c } //2
		$a_03_1 = {6a 04 68 00 10 00 00 68 00 30 03 00 6a 00 ff 15 [0-04] 8b f0 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}