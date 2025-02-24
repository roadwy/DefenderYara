
rule Trojan_Win32_Neoreblamy_NLI_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NLI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_01_0 = {eb e6 6a 04 58 6b c0 00 6a 04 59 6b c9 00 } //2
		$a_01_1 = {eb 04 83 65 c8 00 8b 45 fc 3b 45 c8 75 09 } //2
		$a_03_2 = {40 6a 04 59 c1 e1 00 89 84 0d ?? ?? ff ff 6a 04 58 c1 e0 00 } //1
		$a_03_3 = {50 33 d2 42 33 c9 e8 ?? ?? ff ff 59 59 8b f0 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=6
 
}