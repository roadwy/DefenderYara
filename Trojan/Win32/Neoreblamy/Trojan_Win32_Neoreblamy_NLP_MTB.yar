
rule Trojan_Win32_Neoreblamy_NLP_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NLP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 9c 40 89 45 9c 83 7d 9c 02 7d 10 8b 45 } //2
		$a_03_1 = {6a 04 58 c1 e0 00 8b 84 05 ?? ?? ?? ff 6a 04 59 6b c9 00 } //1
		$a_03_2 = {19 6a 04 58 d1 e0 8b 84 05 ?? ?? ?? ff 48 6a 04 59 d1 e1 89 84 0d ?? ?? ff ff 6a 04 58 d1 e0 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=4
 
}