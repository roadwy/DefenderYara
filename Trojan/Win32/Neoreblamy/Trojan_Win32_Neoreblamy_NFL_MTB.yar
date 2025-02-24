
rule Trojan_Win32_Neoreblamy_NFL_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NFL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {eb 1b 6a 04 58 6b c0 00 8b 84 05 ?? fe ff ff 40 6a 04 59 6b c9 00 89 84 0d ?? fe ff ff 6a 04 58 6b c0 00 } //1
		$a_01_1 = {eb 07 8b 45 94 40 89 45 94 83 7d 94 01 7d 10 8b 45 94 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}