
rule Trojan_Win32_Neoreblamy_NJC_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NJC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {eb 07 8b 45 c0 40 89 45 c0 83 7d c0 ?? 7d 10 8b 45 c0 } //1
		$a_03_1 = {6a 04 58 6b c0 00 8b 84 05 ?? ?? ff ff 89 45 d4 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}