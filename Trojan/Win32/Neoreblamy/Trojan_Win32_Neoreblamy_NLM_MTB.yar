
rule Trojan_Win32_Neoreblamy_NLM_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NLM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 80 40 89 45 80 83 7d 80 04 7d 10 8b 45 80 } //2
		$a_01_1 = {eb 07 8b 45 90 48 89 45 90 83 7d 90 e7 } //1
		$a_03_2 = {eb 1b 6a 04 58 c1 e0 00 8b 84 05 ?? ?? ff ff 48 6a 04 59 c1 e1 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=4
 
}