
rule Trojan_Win32_Neoreblamy_NLJ_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NLJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 b0 48 89 45 b0 83 7d b0 00 7c 2e } //2
		$a_03_1 = {6a 04 59 6b c9 00 0f af 84 0d ?? fe ff ff 6a 04 59 c1 e1 00 } //1
		$a_03_2 = {eb da 6a 04 58 6b c0 00 c7 44 05 a0 ?? ff ff ff eb 15 6a 04 58 6b c0 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=4
 
}