
rule Trojan_Win32_Neoreblamy_NFG_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NFG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {eb 1b 6a 04 58 6b c0 00 8b 84 05 ?? ff ff ff 48 6a 04 59 6b c9 00 89 84 0d ?? ff ff ff 6a 04 58 6b c0 00 } //2
		$a_01_1 = {eb 07 8b 45 f8 40 89 45 f8 83 7d f8 01 7d 10 8b 45 f8 } //1
		$a_03_2 = {eb e3 6a 04 58 6b c0 00 8b 84 05 ?? ff ff ff 89 85 ?? ?? ff ff 6a 04 58 c1 e0 00 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=4
 
}