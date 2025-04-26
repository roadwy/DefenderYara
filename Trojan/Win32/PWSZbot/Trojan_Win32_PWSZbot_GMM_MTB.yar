
rule Trojan_Win32_PWSZbot_GMM_MTB{
	meta:
		description = "Trojan:Win32/PWSZbot.GMM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b c8 8b 75 08 8a 0e 8a 07 3b c1 75 08 85 c0 74 07 46 47 eb f0 33 c0 40 5f 5e 8b e5 5d c2 08 00 } //10
		$a_01_1 = {8a 07 32 c3 88 06 47 2b f2 49 75 f4 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}