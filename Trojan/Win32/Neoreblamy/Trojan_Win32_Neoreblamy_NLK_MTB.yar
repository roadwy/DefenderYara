
rule Trojan_Win32_Neoreblamy_NLK_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NLK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {eb 08 8b 45 e4 40 40 89 45 e4 83 7d e4 06 } //2
		$a_01_1 = {eb 07 8b 45 ec 48 89 45 ec 83 7d ec 00 7c 10 8b 45 ec } //1
		$a_03_2 = {6a 04 58 6b c0 00 8b 44 05 84 89 85 ?? ?? ff ff 6a 04 58 c1 e0 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=4
 
}