
rule Trojan_Win32_Neoreblamy_NR_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {eb 07 8b 45 f8 40 89 45 f8 83 7d f8 01 7d 10 8b 45 f8 c7 84 85 ?? ?? ff ff ff ff ff ff eb e3 c7 45 f8 } //1
		$a_03_1 = {6a 04 58 6b c0 00 c7 44 05 88 ?? ff ff ff eb 15 6a 04 58 6b c0 00 8b 44 05 88 48 6a 04 59 6b c9 00 89 44 0d 88 6a 04 58 6b c0 00 } //2
		$a_01_2 = {eb 15 6a 04 58 6b c0 00 8b 44 05 88 48 6a 04 59 6b c9 00 89 44 0d 88 6a 04 58 6b c0 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=4
 
}