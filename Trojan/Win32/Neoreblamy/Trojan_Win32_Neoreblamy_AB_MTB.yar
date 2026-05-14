
rule Trojan_Win32_Neoreblamy_AB_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 02 00 00 "
		
	strings :
		$a_01_0 = {6a 39 59 33 d2 8b c6 f7 f1 6b c8 39 8b c6 2b c1 8b 4d 08 ff 34 81 ff 34 b3 e8 5e fb ff ff 89 04 b3 46 59 59 3b f7 72 d8 } //6
		$a_81_1 = {64 54 4d 64 79 55 4e 69 75 54 56 68 78 56 71 67 72 } //2 dTMdyUNiuTVhxVqgr
	condition:
		((#a_01_0  & 1)*6+(#a_81_1  & 1)*2) >=8
 
}