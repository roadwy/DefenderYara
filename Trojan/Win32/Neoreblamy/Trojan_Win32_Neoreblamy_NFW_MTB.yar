
rule Trojan_Win32_Neoreblamy_NFW_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NFW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 d8 40 89 45 d8 83 7d d8 01 7d 10 8b 45 d8 } //1
		$a_01_1 = {48 6a 04 59 6b c9 00 89 84 0d 30 ff ff ff 6a 04 58 6b c0 00 } //1
		$a_03_2 = {eb 1b 6a 04 58 c1 e0 00 8b 84 05 ?? ?? ff ff 48 6a 04 59 c1 e1 00 89 84 0d ?? ?? ff ff 6a 04 58 c1 e0 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2) >=4
 
}