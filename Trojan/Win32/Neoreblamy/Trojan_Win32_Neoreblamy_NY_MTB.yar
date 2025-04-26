
rule Trojan_Win32_Neoreblamy_NY_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {eb 08 8b 45 e8 40 40 89 45 e8 83 7d e8 24 0f 83 ?? ?? 00 00 33 c0 40 6b c0 00 } //2
		$a_01_1 = {eb 07 8b 45 98 40 89 45 98 83 7d 98 01 7d 10 8b 45 98 c7 84 85 } //1
		$a_03_2 = {eb 1b 6a 04 58 6b c0 03 8b 84 05 ?? ?? ff ff 48 6a 04 59 6b c9 03 89 84 0d ?? ?? ff ff 6a 04 58 6b c0 03 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=4
 
}