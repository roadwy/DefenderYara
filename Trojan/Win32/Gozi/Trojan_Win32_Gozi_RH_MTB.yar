
rule Trojan_Win32_Gozi_RH_MTB{
	meta:
		description = "Trojan:Win32/Gozi.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {66 36 4c 2e 64 6c 6c } //1 f6L.dll
		$a_01_1 = {45 47 42 56 70 6b 75 65 73 4a 77 42 64 78 } //1 EGBVpkuesJwBdx
		$a_01_2 = {4a 4e 6e 76 71 41 4b 75 4d 70 6e 66 52 49 73 63 } //1 JNnvqAKuMpnfRIsc
		$a_01_3 = {4b 77 6a 45 4b 71 51 51 5a 68 75 } //1 KwjEKqQQZhu
		$a_01_4 = {50 65 58 50 73 79 69 7a 72 53 67 6a } //1 PeXPsyizrSgj
		$a_01_5 = {73 75 4e 54 54 43 68 69 6c 47 47 77 56 65 4d } //1 suNTTChilGGwVeM
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}