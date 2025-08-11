
rule Trojan_Win32_Neoreblamy_NFX_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NFX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {eb 07 83 a5 60 fe ff ff 00 6a 04 58 d1 e0 } //1
		$a_01_1 = {eb 07 8b 45 f4 40 89 45 f4 83 7d f4 04 7d 10 8b 45 f4 } //1
		$a_03_2 = {1b 6a 04 58 6b c0 03 8b 84 05 ?? ?? ff ff 40 6a 04 59 6b c9 03 89 84 0d ?? ?? ff ff 6a 04 58 6b c0 03 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2) >=4
 
}